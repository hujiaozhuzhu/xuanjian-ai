"""
玄鉴 v2.3.0 — 规则自动调优模块测试

测试覆盖率目标: >= 95%
测试子功能: 自动调优 (AutoTuner)

版本: 2.3.0
"""

import asyncio
import json
import os
import tempfile
import pytest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch, MagicMock

from fp_sentinel.rule_optimization.auto_tuner import (
    AutoTuner,
    THRESHOLD_BOUNDARIES,
    MAX_ADJUSTMENT_STEP,
    MIN_FP_SAMPLES,
    TARGET_FP_REDUCTION,
    TuningResult,
    TuningReport,
    FalsePositiveSample,
)


# ─────────────────────── Fixtures ───────────────────────

@pytest.fixture
def tuner():
    """创建默认 AutoTuner 实例"""
    return AutoTuner()


@pytest.fixture
def temp_dir():
    """临时目录"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def sample_fp_data():
    """生成标准误报样本数据（200条，均匀分布到L1/L2/L3）"""
    samples = []
    import random
    random.seed(42)

    for layer in ["L1", "L2", "L3"]:
        base_conf = {"L1": 0.82, "L2": 0.78, "L3": 0.85}[layer]
        for i in range(67 if layer != "L3" else 66):
            conf = base_conf + random.uniform(-0.1, 0.1)
            conf = max(0.3, min(0.99, conf))
            sample = FalsePositiveSample(
                fingerprint=f"fp_{layer.lower()}_{i:04d}",
                layer=layer,
                rule_id=f"test.rule.{layer.lower()}.{i % 5}",
                tool="semgrep",
                severity=random.choice(["HIGH", "MEDIUM", "LOW"]),
                file_path=f"src/main/java/com/example/File{i}.java",
                code_snippet=f"Sample code {i}",
                confidence_when_marked=round(conf, 4),
                marked_at=datetime.now().isoformat(),
                filter_reasons=[f"{layer}_rule_match"],
            )
            samples.append(sample)
    return samples


@pytest.fixture
def tuner_with_samples(tuner, sample_fp_data):
    """加载样本数据的 tuner"""
    for sample in sample_fp_data:
        tuner.add_fp_sample(sample)
    return tuner


@pytest.fixture
def fp_json_file(temp_dir, sample_fp_data):
    """创建 JSON 格式的误报样本文件"""
    data = {
        "version": "2.3.0",
        "total": len(sample_fp_data),
        "generated_at": datetime.now().isoformat(),
        "samples": [
            {
                "fingerprint": s.fingerprint,
                "layer": s.layer,
                "rule_id": s.rule_id,
                "tool": s.tool,
                "severity": s.severity,
                "file_path": s.file_path,
                "code_snippet": s.code_snippet,
                "confidence_when_marked": s.confidence_when_marked,
                "marked_at": s.marked_at,
                "filter_reasons": s.filter_reasons,
            }
            for s in sample_fp_data
        ],
    }

    file_path = Path(temp_dir) / "fp_samples.json"
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    return str(file_path)


@pytest.fixture
def fp_json_dir(temp_dir, sample_fp_data):
    """创建包含多个 JSON 文件的目录"""
    dir_path = Path(temp_dir) / "fp_data"
    dir_path.mkdir()

    # 将样本分为3个文件
    third = len(sample_fp_data) // 3
    for idx, start in enumerate(range(0, len(sample_fp_data), third)):
        chunk = sample_fp_data[start:start + third]
        data = {
            "version": "2.3.0",
            "samples": [
                {
                    "fingerprint": s.fingerprint,
                    "layer": s.layer,
                    "rule_id": s.rule_id,
                    "tool": s.tool,
                    "severity": s.severity,
                    "file_path": s.file_path,
                    "code_snippet": s.code_snippet,
                    "confidence_when_marked": s.confidence_when_marked,
                    "marked_at": s.marked_at,
                    "filter_reasons": s.filter_reasons,
                }
                for s in chunk
            ],
        }
        file_path = dir_path / f"fp_batch_{idx}.json"
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    return str(dir_path)


# ─────────────────────── 常量测试 ───────────────────────

class TestConstants:
    """常量定义测试"""

    def test_threshold_boundaries_exist(self):
        assert "L1" in THRESHOLD_BOUNDARIES
        assert "L2" in THRESHOLD_BOUNDARIES
        assert "L3" in THRESHOLD_BOUNDARIES

    def test_threshold_boundaries_valid(self):
        for layer in ["L1", "L2", "L3"]:
            b = THRESHOLD_BOUNDARIES[layer]
            assert b["min_confidence"] < b["max_confidence"]
            assert b["min_confidence"] <= b["default"] <= b["max_confidence"]
            assert 0.0 <= b["min_confidence"] < b["max_confidence"] <= 1.0

    def test_max_adjustment_step_valid(self):
        assert 0 < MAX_ADJUSTMENT_STEP <= 0.2

    def test_min_fp_samples_valid(self):
        assert MIN_FP_SAMPLES >= 5

    def test_target_fp_reduction(self):
        assert TARGET_FP_REDUCTION >= 15.0


# ─────────────────────── AutoTuner 初始化测试 ───────────────────────

class TestAutoTunerInit:
    """初始化测试"""

    def test_default_init(self):
        tuner = AutoTuner()
        assert tuner.fp_data_path is None
        assert tuner._fp_samples == []
        assert len(tuner.current_thresholds) == 3

    def test_init_with_path(self, temp_dir):
        path = os.path.join(temp_dir, "fp.json")
        tuner = AutoTuner(fp_data_path=path)
        assert tuner.fp_data_path == path

    def test_init_with_config(self):
        config = {
            "fp_data_config": "test.json",
            "baseline_path": "baseline.json",
        }
        tuner = AutoTuner(config=config)
        assert tuner.config == config

    def test_default_thresholds_loaded(self):
        tuner = AutoTuner()
        assert tuner.current_thresholds["L1"] == THRESHOLD_BOUNDARIES["L1"]["default"]
        assert tuner.current_thresholds["L2"] == THRESHOLD_BOUNDARIES["L2"]["default"]
        assert tuner.current_thresholds["L3"] == THRESHOLD_BOUNDARIES["L3"]["default"]


# ─────────────────────── 数据加载测试 ───────────────────────

class TestDataLoading:
    """数据加载测试"""

    def test_load_from_json_file(self, tuner, fp_json_file):
        count = tuner.load_fp_samples(fp_json_file)
        assert count > 0
        assert len(tuner._fp_samples) == count

    def test_load_from_directory(self, tuner, fp_json_dir):
        count = tuner.load_fp_samples(fp_json_dir)
        assert count > 0
        samples_by_layer = tuner._fp_samples_by_layer
        assert len(samples_by_layer["L1"]) > 0
        assert len(samples_by_layer["L2"]) > 0
        assert len(samples_by_layer["L3"]) > 0

    def test_load_nonexistent_path(self, tuner):
        count = tuner.load_fp_samples("/nonexistent/path/fp.json")
        assert count == 0

    def test_load_no_path_set(self):
        tuner = AutoTuner()
        count = tuner.load_fp_samples()
        assert count == 0

    def test_load_empty_json(self, tuner, temp_dir):
        file_path = Path(temp_dir) / "empty.json"
        with open(file_path, 'w') as f:
            json.dump({"samples": []}, f)
        count = tuner.load_fp_samples(str(file_path))
        assert count == 0

    def test_load_malformed_json(self, tuner, temp_dir):
        file_path = Path(temp_dir) / "bad.json"
        with open(file_path, 'w') as f:
            f.write("{ broken json")
        count = tuner.load_fp_samples(str(file_path))
        assert count == 0

    def test_load_list_format(self, tuner, temp_dir):
        file_path = Path(temp_dir) / "list_format.json"
        data = [
            {
                "fingerprint": "fp_001",
                "layer": "L1",
                "rule_id": "test.rule",
                "tool": "semgrep",
                "severity": "HIGH",
                "file_path": "test.java",
                "code_snippet": "code",
                "confidence_when_marked": 0.8,
                "marked_at": datetime.now().isoformat(),
            }
        ]
        with open(file_path, 'w') as f:
            json.dump(data, f)
        count = tuner.load_fp_samples(str(file_path))
        assert count == 1

    def test_add_fp_sample_manual(self, tuner):
        sample = FalsePositiveSample(
            fingerprint="manual_fp_001",
            layer="L2",
            rule_id="java.sql.injection",
            tool="findsecbugs",
            severity="MEDIUM",
            file_path="src/test/Test.java",
            code_snippet="String sql = \"SELECT 1\"",
            confidence_when_marked=0.85,
            marked_at=datetime.now().isoformat(),
            filter_reasons=["L2_test_file"],
        )
        tuner.add_fp_sample(sample)
        assert len(tuner._fp_samples) == 1
        assert len(tuner._fp_samples_by_layer["L2"]) == 1

    def test_add_fp_sample_unknown_layer(self, tuner):
        sample = FalsePositiveSample(
            fingerprint="fp_unknown",
            layer="unknown",
            rule_id="test",
            tool="test",
            severity="LOW",
            file_path="test.java",
            code_snippet="code",
            confidence_when_marked=0.6,
            marked_at=datetime.now().isoformat(),
        )
        tuner.add_fp_sample(sample)
        assert len(tuner._fp_samples) == 1
        assert "unknown" not in tuner._fp_samples_by_layer


# ─────────────────────── 调优计算测试 ───────────────────────

class TestTuningCalculation:
    """调优计算测试"""

    @pytest.mark.asyncio
    async def test_tune_layer_insufficient_samples(self, tuner):
        """样本不足时返回 None"""
        result = await tuner.tune_layer("L1")
        assert result is None

    @pytest.mark.asyncio
    async def test_tune_single_layer(self, tuner_with_samples):
        """对单层调优"""
        result = await tuner_with_samples.tune_layer("L1")
        assert result is not None
        assert result.layer == "L1"
        assert result.fp_samples_analyzed >= MIN_FP_SAMPLES
        assert THRESHOLD_BOUNDARIES["L1"]["min_confidence"] <= result.new_threshold <= THRESHOLD_BOUNDARIES["L1"]["max_confidence"]
        assert result.confidence > 0

    @pytest.mark.asyncio
    async def test_tune_all_layers(self, tuner_with_samples):
        """三层全部调优"""
        report = await tuner_with_samples.tune_all_layers()
        assert isinstance(report, TuningReport)
        assert len(report.results) == 3
        assert report.total_fp_samples == len(sample_fp_data_fixture(tuner_with_samples))
        assert report.overall_predicted_reduction >= 0

    @pytest.mark.asyncio
    async def test_tune_l2(self, tuner_with_samples):
        """L2 层调优"""
        result = await tuner_with_samples.tune_layer("L2")
        assert result is not None
        assert result.layer == "L2"
        assert abs(result.adjustment) <= MAX_ADJUSTMENT_STEP + 0.001  # 允许浮点误差

    @pytest.mark.asyncio
    async def test_tune_l3(self, tuner_with_samples):
        """L3 层调优"""
        result = await tuner_with_samples.tune_layer("L3")
        assert result is not None
        assert result.layer == "L3"

    @pytest.mark.asyncio
    async def test_tuning_result_within_bounds(self, tuner_with_samples):
        """调优结果在安全边界内"""
        report = await tuner_with_samples.tune_all_layers()
        for result in report.results:
            layer = result.layer
            boundaries = THRESHOLD_BOUNDARIES[layer]
            assert result.new_threshold >= boundaries["min_confidence"] - 0.001
            assert result.new_threshold <= boundaries["max_confidence"] + 0.001

    @pytest.mark.asyncio
    async def test_tuning_report_json_serializable(self, tuner_with_samples):
        """调优报告可序列化"""
        report = await tuner_with_samples.tune_all_layers()
        json_str = report.to_json()
        parsed = json.loads(json_str)
        assert "version" in parsed
        assert parsed["version"] == "2.3.0"
        assert "layer_results" in parsed
        assert len(parsed["layer_results"]) == 3


def sample_fp_data_fixture(tuner):
    """获取 tuner 中的样本列表"""
    return tuner._fp_samples


# ─────────────────────── 阈值应用测试 ───────────────────────

class TestThresholdApplication:
    """阈值应用测试"""

    @pytest.mark.asyncio
    async def test_apply_thresholds(self, tuner_with_samples):
        """应用调优阈值"""
        report = await tuner_with_samples.tune_all_layers()
        old_thresholds = dict(tuner_with_samples.current_thresholds)
        new_thresholds = tuner_with_samples.apply_thresholds(report)

        assert "L1" in new_thresholds
        assert "L2" in new_thresholds
        assert "L3" in new_thresholds

    def test_apply_empty_report(self, tuner):
        """空报告不修改阈值"""
        report = TuningReport()
        old = dict(tuner.current_thresholds)
        tuner.apply_thresholds(report)
        assert tuner.current_thresholds == old


# ─────────────────────── 回滚测试 ───────────────────────

class TestRollback:
    """回滚功能测试"""

    @pytest.mark.asyncio
    async def test_rollback_single_step(self, tuner_with_samples):
        """单步回滚"""
        report = await tuner_with_samples.tune_all_layers()
        tuner_with_samples.apply_thresholds(report)

        old_l1 = tuner_with_samples.current_thresholds["L1"]
        success = await tuner_with_samples.rollback(1)

        assert success is True
        # 回滚后阈值应该恢复
        assert tuner_with_samples.current_thresholds["L1"] != old_l1 or report.results[0].adjustment == 0

    @pytest.mark.asyncio
    async def test_rollback_multiple_steps(self, tuner_with_samples):
        """多步回滚"""
        # 第一次调优
        report1 = await tuner_with_samples.tune_all_layers()
        tuner_with_samples.apply_thresholds(report1)
        after_first = dict(tuner_with_samples.current_thresholds)

        # 改变数据后第二次调优
        report2 = await tuner_with_samples.tune_all_layers()
        tuner_with_samples.apply_thresholds(report2)
        after_second = dict(tuner_with_samples.current_thresholds)

        # 回滚1步
        success = await tuner_with_samples.rollback(1)
        assert success is True
        # 再次回滚
        success2 = await tuner_with_samples.rollback(1)
        assert success2 is True

    def test_rollback_exceeds_history(self, tuner):
        """回滚超过历史深度时失败"""
        success = asyncio.run(tuner.rollback(5))
        assert success is False


# ─────────────────────── 持久化测试 ───────────────────────

class TestPersistence:
    """持久化测试"""

    @pytest.mark.asyncio
    async def test_save_report(self, tuner_with_samples, temp_dir):
        """保存调优报告"""
        report = await tuner_with_samples.tune_all_layers()
        output_path = os.path.join(temp_dir, "reports", "tuning")
        saved_path = tuner_with_samples.save_report(report, output_dir=output_path)

        assert os.path.exists(saved_path)
        with open(saved_path, 'r', encoding='utf-8') as f:
            saved_data = json.load(f)
        assert saved_data["version"] == "2.3.0"

    def test_save_thresholds(self, tuner, temp_dir):
        """保存阈值配置"""
        file_path = os.path.join(temp_dir, "thresholds.json")
        saved_path = tuner.save_thresholds(file_path)

        assert os.path.exists(saved_path)
        with open(saved_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        assert "thresholds" in data
        assert data["version"] == "2.3.0"

    def test_load_thresholds(self, tuner, temp_dir):
        """加载阈值配置"""
        file_path = os.path.join(temp_dir, "thresholds.json")
        tuner.save_thresholds(file_path)

        # 修改当前阈值
        tuner.current_thresholds["L1"] = 0.99

        # 加载
        loaded = tuner.load_thresholds(file_path)
        assert loaded["L1"] == THRESHOLD_BOUNDARIES["L1"]["default"]

    def test_load_nonexistent_thresholds(self, tuner):
        """加载不存在的阈值文件返回默认值"""
        loaded = tuner.load_thresholds("/nonexistent/thresholds.json")
        assert loaded == tuner.current_thresholds

    def test_save_report_creates_directory(self, tuner, temp_dir):
        """保存报告时自动创建目录"""
        report = TuningReport()
        output_path = os.path.join(temp_dir, "deep", "nested", "path")
        saved_path = tuner.save_report(report, output_dir=output_path)
        assert os.path.exists(saved_path)


# ─────────────────────── 统计方法测试 ───────────────────────

class TestStatistics:
    """统计方法测试"""

    def test_calc_std_normal(self, tuner):
        values = [0.7, 0.8, 0.9, 0.75, 0.85]
        std = tuner._calc_std(values)
        assert std > 0

    def test_calc_std_single_value(self, tuner):
        std = tuner._calc_std([0.5])
        assert std == 0.0

    def test_calc_std_empty(self, tuner):
        std = tuner._calc_std([])
        assert std == 0.0

    def test_calc_std_identical(self, tuner):
        std = tuner._calc_std([0.8, 0.8, 0.8])
        assert abs(std) < 1e-10  # 浮点精度容忍

    def test_estimate_reduction_increase(self, tuner):
        """阈值提高时应产生正降低率"""
        samples = [
            FalsePositiveSample(
                fingerprint=f"fp_{i}",
                layer="L1",
                rule_id="test",
                tool="semgrep",
                severity="HIGH",
                file_path="test.java",
                code_snippet="code",
                confidence_when_marked=0.7 + i * 0.01,
                marked_at=datetime.now().isoformat(),
            )
            for i in range(20)
        ]
        reduction = tuner._estimate_reduction(samples, 0.6, 0.8)
        assert reduction > 0

    def test_estimate_reduction_no_change(self, tuner):
        """阈值不变时降低率为0"""
        samples = [
            FalsePositiveSample(
                fingerprint=f"fp_{i}",
                layer="L1",
                rule_id="test",
                tool="semgrep",
                severity="HIGH",
                file_path="test.java",
                code_snippet="code",
                confidence_when_marked=0.8,
                marked_at=datetime.now().isoformat(),
            )
            for i in range(10)
        ]
        reduction = tuner._estimate_reduction(samples, 0.7, 0.7)
        assert reduction == 0.0

    def test_estimate_reduction_decrease(self, tuner):
        """阈值降低时降低率为0"""
        samples = [
            FalsePositiveSample(
                fingerprint=f"fp_{i}",
                layer="L1",
                rule_id="test",
                tool="semgrep",
                severity="HIGH",
                file_path="test.java",
                code_snippet="code",
                confidence_when_marked=0.8,
                marked_at=datetime.now().isoformat(),
            )
            for i in range(10)
        ]
        reduction = tuner._estimate_reduction(samples, 0.8, 0.6)
        assert reduction == 0.0


# ─────────────────────── TuningResult 测试 ───────────────────────

class TestTuningResult:
    """TuningResult 数据模型测试"""

    def test_to_dict(self):
        result = TuningResult(
            layer="L1",
            previous_threshold=0.7,
            new_threshold=0.75,
            adjustment=0.05,
            fp_samples_analyzed=50,
            predicted_reduction_pct=18.5,
            confidence=0.9,
        )
        d = result.to_dict()
        assert d["layer"] == "L1"
        assert d["new_threshold"] == 0.75
        assert d["fp_samples_analyzed"] == 50

    def test_tuning_report_serializable(self):
        result = TuningResult(
            layer="L2",
            previous_threshold=0.5,
            new_threshold=0.55,
            adjustment=0.05,
            fp_samples_analyzed=30,
            predicted_reduction_pct=16.0,
            confidence=0.85,
        )
        report = TuningReport(results=[result])
        report.total_fp_samples = 100
        report.overall_predicted_reduction = 16.0

        json_str = report.to_json()
        parsed = json.loads(json_str)
        assert parsed["overall_predicted_reduction_pct"] == 16.0


# ─────────────────────── 生成合成数据测试 ───────────────────────

class TestSyntheticDataGeneration:
    """合成数据生成测试"""

    def test_generate_synthetic_to_memory(self, tuner):
        """生成到内存"""
        result = tuner.generate_synthetic_fp_data(count=50, seed=42)
        assert result == "memory"
        assert len(tuner._fp_samples) == 50

    def test_generate_synthetic_to_file(self, tuner, temp_dir):
        """生成到文件"""
        file_path = os.path.join(temp_dir, "synthetic_fp.json")
        result = tuner.generate_synthetic_fp_data(count=100, output_path=file_path, seed=42)
        assert result == file_path
        assert os.path.exists(file_path)
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        assert data["total"] == 100
        assert len(data["samples"]) == 100

    def test_synthetic_data_distribution(self, tuner):
        """合成数据分层分布"""
        tuner.generate_synthetic_fp_data(count=300, seed=42)
        by_layer = tuner._fp_samples_by_layer
        assert len(by_layer["L1"]) > 0
        assert len(by_layer["L2"]) > 0
        assert len(by_layer["L3"]) > 0


# ─────────────────────── 集成场景测试 ───────────────────────

class TestIntegrationScenarios:
    """集成场景测试"""

    @pytest.mark.asyncio
    async def test_full_pipeline(self, temp_dir, fp_json_file):
        """完整流程: 加载 -> 调优 -> 应用 -> 保存"""
        tuner = AutoTuner(fp_data_path=fp_json_file)

        # 加载数据
        count = tuner.load_fp_samples()
        assert count > 0

        # 加载已保存的阈值
        baseline_path = os.path.join(temp_dir, "baseline.json")
        tuner.load_thresholds(baseline_path)

        # 调优
        report = await tuner.tune_all_layers()
        assert len(report.results) > 0
        assert report.overall_predicted_reduction >= 0

        # 应用阈值
        new_thresholds = tuner.apply_thresholds(report)
        assert new_thresholds is not None

        # 保存报告
        report_path = tuner.save_report(report, output_dir=os.path.join(temp_dir, "reports"))
        assert os.path.exists(report_path)

        # 保存阈值
        thresh_path = tuner.save_thresholds(baseline_path)
        assert os.path.exists(thresh_path)

        # 回滚
        await tuner.rollback(1)

    @pytest.mark.asyncio
    async def test_repeated_tuning_convergence(self, tuner_with_samples):
        """重复调优趋向收敛"""
        prev_thresholds = dict(tuner_with_samples.current_thresholds)

        for _ in range(3):
            report = await tuner_with_samples.tune_all_layers()
            tuner_with_samples.apply_thresholds(report)

        # 调整幅度应该逐步减小
        for _ in range(2):
            report = await tuner_with_samples.tune_all_layers()
            for result in report.results:
                assert abs(result.adjustment) <= MAX_ADJUSTMENT_STEP + 0.001

    @pytest.mark.asyncio
    async def test_scale_with_large_dataset(self, tuner):
        """大规模数据测试"""
        # 生成1000条合成数据
        tuner.generate_synthetic_fp_data(count=1000, seed=123)

        report = await tuner.tune_all_layers()
        assert len(report.results) == 3
        assert report.total_fp_samples == 1000

        for result in report.results:
            assert result.confidence > 0.8  # 大数据量下置信度应该高


# ─────────────────────── 边界情况测试 ───────────────────────

class TestEdgeCases:
    """边界情况测试"""

    def test_parse_sample_missing_fingerprint(self, tuner):
        """缺失 fingerprint 时返回 None"""
        bad_data = {"layer": "L1", "rule_id": "test"}
        result = tuner._parse_single_sample(bad_data)
        assert result is None

    def test_parse_sample_invalid_confidence(self, tuner):
        """无效 confidence 时返回 None"""
        bad_data = {
            "fingerprint": "fp_test",
            "layer": "L1",
            "confidence_when_marked": "not_a_number",
        }
        result = tuner._parse_single_sample(bad_data)
        assert result is None

    def test_estimate_reduction_empty_samples(self, tuner):
        """空样本列表时降低率为0"""
        reduction = tuner._estimate_reduction([], 0.6, 0.8)
        assert reduction == 0.0

    @pytest.mark.asyncio
    async def test_tune_unknown_layer(self, tuner_with_samples):
        """未知层级不报错，但返回None"""
        result = await tuner_with_samples.tune_layer("L99")
        assert result is None

    def test_threshold_too_high_clamped(self, tuner):
        """阈值不超过上界"""
        confidences = [0.99] * 100
        new_t = tuner._calc_optimal_threshold(
            current_threshold=0.7,
            mean_fp_confidence=sum(confidences) / len(confidences),
            std_fp_confidence=0.0,
            sample_count=100,
            min_bound=0.4,
            max_bound=0.95,
        )
        assert new_t <= 0.95

    def test_threshold_too_low_clamped(self, tuner):
        """阈值不低于下界"""
        confidences = [0.3] * 100
        new_t = tuner._calc_optimal_threshold(
            current_threshold=0.5,
            mean_fp_confidence=sum(confidences) / len(confidences),
            std_fp_confidence=0.0,
            sample_count=100,
            min_bound=0.4,
            max_bound=0.95,
        )
        assert new_t >= 0.4
