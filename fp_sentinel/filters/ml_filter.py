"""
L3: 机器学习过滤器

使用机器学习模型评估漏洞真实性，支持：
- 特征提取
- 模型训练与推理
- 置信度评分
- 启发式预测（无模型时）
"""

import pickle
import hashlib
import logging
from typing import List, Optional, Dict, Any, Tuple
from pathlib import Path
from ..models import ScanResult, FilterResult, FilterReason, Verdict


logger = logging.getLogger(__name__)


class MLFilter:
    """L3 机器学习过滤器"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
        self.model_path = self.config.get("model_path", "models/fp_model.pkl")
        self.confidence_threshold = self.config.get("confidence_threshold", 0.7)

        self.feature_columns = self.config.get("feature_columns", [
            "rule_confidence", "severity_score", "code_complexity",
            "data_flow_length", "has_security_guards", "has_input_validation",
            "is_test_code", "file_depth", "line_count",
        ])

        self.model = None
        self.onnx_session = None
        self._load_model()

    def _load_model(self):
        """加载机器学习模型"""
        try:
            onnx_path = self.config.get("onnx_model_path", "models/fp_model.onnx")
            if Path(onnx_path).exists():
                import onnxruntime as ort
                self.onnx_session = ort.InferenceSession(onnx_path)
                logger.info(f"Loaded ONNX model: {onnx_path}")
                return

            if Path(self.model_path).exists():
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                logger.info(f"Loaded pickle model: {self.model_path}")
                return

            logger.info("No pre-trained model found, using heuristic prediction")
        except Exception as e:
            logger.warning(f"Failed to load model: {e}")

    async def filter(self, scan_result: ScanResult) -> FilterResult:
        """过滤单条扫描结果"""
        if not self.enabled:
            return self._pass_through(scan_result)

        features = self._extract_features(scan_result)
        is_fp, confidence = self._predict(features)
        reasons = self._gen_reasons(features, is_fp, confidence)

        if is_fp and confidence >= self.confidence_threshold:
            verdict = Verdict.LIKELY_FALSE_POSITIVE
        else:
            verdict = Verdict.NEEDS_REVIEW

        return FilterResult(
            id=scan_result.id,
            original=scan_result,
            verdict=verdict,
            confidence=confidence,
            filter_reasons=reasons,
            risk_score=self._calc_risk(scan_result, is_fp, confidence),
            recommendation=self._gen_recommendation(verdict, confidence),
        )

    def _extract_features(self, scan_result: ScanResult) -> Dict[str, float]:
        """提取特征"""
        features = {}

        # 规则置信度
        features["rule_confidence"] = self._rule_confidence(scan_result.rule_id)

        # 严重程度
        sev_map = {"CRITICAL": 1.0, "HIGH": 0.85, "MEDIUM": 0.6, "LOW": 0.35, "INFO": 0.15}
        features["severity_score"] = sev_map.get(scan_result.severity.value, 0.5)

        # 代码复杂度
        features["code_complexity"] = self._code_complexity(scan_result.code)

        # 数据流长度
        features["data_flow_length"] = float(scan_result.metadata.get("data_flow_length", 5))

        # 安全守卫
        features["has_security_guards"] = float(
            scan_result.metadata.get("has_security_guards", False)
        )

        # 输入验证
        features["has_input_validation"] = float(
            scan_result.metadata.get("has_input_validation", False)
        )

        # 测试代码
        features["is_test_code"] = float(self._is_test(scan_result.file))

        # 文件深度
        features["file_depth"] = float(len(scan_result.file.split('/')))

        # 代码行数
        features["line_count"] = float(len(scan_result.code.split('\n')))

        return features

    def _rule_confidence(self, rule_id: str) -> float:
        """基于规则ID的启发式置信度"""
        rid = rule_id.lower()
        high = ["sql-injection", "xss", "command-injection", "path-traversal", "rce", "deserialization"]
        medium = ["hardcoded-password", "hardcoded-secret", "insecure-random", "weak-crypto", "ssrf"]
        for p in high:
            if p in rid:
                return 0.9
        for p in medium:
            if p in rid:
                return 0.7
        return 0.5

    def _code_complexity(self, code: str) -> float:
        score = 0.0
        for kw in ['if', 'else', 'for', 'while', 'switch', 'try', 'catch', 'except']:
            score += code.count(kw) * 0.1
        score += code.count('(') * 0.05
        return min(1.0, score)

    def _is_test(self, file_path: str) -> bool:
        fp = file_path.lower()
        return any(p in fp for p in [
            "test_", "_test.", "tests/", "test/",
            "Test.java", "Tests.java", "__tests__",
        ])

    def _predict(self, features: Dict[str, float]) -> Tuple[bool, float]:
        """预测"""
        vec = [features.get(c, 0.0) for c in self.feature_columns]

        # ONNX
        if self.onnx_session:
            try:
                import numpy as np
                arr = np.array([vec], dtype=np.float32)
                inp = self.onnx_session.get_inputs()[0].name
                out = self.onnx_session.get_outputs()[0].name
                pred = self.onnx_session.run([out], {inp: arr})[0]
                prob = float(pred[0][1]) if len(pred.shape) > 1 else float(pred[0])
                return prob > self.confidence_threshold, prob
            except Exception as e:
                logger.warning(f"ONNX inference failed: {e}")

        # sklearn
        if self.model:
            try:
                import numpy as np
                arr = np.array([vec], dtype=np.float32)
                prob = float(self.model.predict_proba(arr)[0][1])
                return prob > self.confidence_threshold, prob
            except Exception as e:
                logger.warning(f"sklearn inference failed: {e}")

        # 启发式
        return self._heuristic(features)

    def _heuristic(self, features: Dict[str, float]) -> Tuple[bool, float]:
        """启发式预测"""
        score = 0.0
        score += features.get("rule_confidence", 0.5) * 0.3
        score += features.get("severity_score", 0.5) * 0.2
        if features.get("has_security_guards"):
            score += 0.2
        if features.get("has_input_validation"):
            score += 0.15
        if features.get("is_test_code"):
            score += 0.1
        score += (1 - features.get("code_complexity", 0.5)) * 0.05

        is_fp = score < 0.5
        confidence = abs(score - 0.5) * 2
        return is_fp, confidence

    def _gen_reasons(
        self, features: Dict[str, float], is_fp: bool, confidence: float
    ) -> List[FilterReason]:
        reasons = []
        if is_fp:
            if features.get("has_security_guards"):
                reasons.append(FilterReason(
                    filter_level="L3", rule_name="ml_security_guards",
                    description="ML模型识别到安全守卫措施", confidence=0.8,
                ))
            if features.get("has_input_validation"):
                reasons.append(FilterReason(
                    filter_level="L3", rule_name="ml_input_validation",
                    description="ML模型识别到输入验证", confidence=0.7,
                ))
            if features.get("is_test_code"):
                reasons.append(FilterReason(
                    filter_level="L3", rule_name="ml_test_code",
                    description="ML模型识别为测试代码", confidence=0.6,
                ))
        if not reasons:
            reasons.append(FilterReason(
                filter_level="L3", rule_name="ml_assessment",
                description=f"ML综合评估，置信度: {confidence:.2f}",
                confidence=confidence,
            ))
        return reasons

    def _calc_risk(self, scan_result: ScanResult, is_fp: bool, confidence: float) -> float:
        base = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 3.0, "INFO": 1.0}.get(
            scan_result.severity.value, 5.0
        )
        if is_fp:
            return round(base * (1 - confidence * 0.8), 2)
        return round(base * confidence, 2)

    def _gen_recommendation(self, verdict: Verdict, confidence: float) -> str:
        if verdict == Verdict.LIKELY_FALSE_POSITIVE:
            return "ML评估表明可能为误报，建议人工确认"
        return "ML评估未发现明显误报特征"

    def _pass_through(self, scan_result: ScanResult) -> FilterResult:
        return FilterResult(
            id=scan_result.id,
            original=scan_result,
            verdict=Verdict.NEEDS_REVIEW,
            confidence=0.5,
            filter_reasons=[],
            risk_score=self._calc_risk(scan_result, False, 0.5),
            recommendation="L3 ML过滤器未启用",
        )

    async def train(
        self, training_data: List[Dict[str, Any]], model_type: str = "random_forest"
    ) -> Dict[str, Any]:
        """训练模型"""
        try:
            from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
            from sklearn.model_selection import train_test_split
            from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
            import numpy as np

            X, y = [], []
            for item in training_data:
                feats = item.get("features", {})
                X.append([feats.get(c, 0.0) for c in self.feature_columns])
                y.append(1 if item.get("is_false_positive", False) else 0)

            X = np.array(X)
            y = np.array(y)

            X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)

            if model_type == "gradient_boosting":
                model = GradientBoostingClassifier(n_estimators=100, random_state=42)
            else:
                model = RandomForestClassifier(n_estimators=100, random_state=42)

            model.fit(X_train, y_train)
            y_pred = model.predict(X_val)

            # 保存模型
            Path(self.model_path).parent.mkdir(parents=True, exist_ok=True)
            with open(self.model_path, 'wb') as f:
                pickle.dump(model, f)
            self.model = model

            return {
                "model_path": self.model_path,
                "accuracy": float(accuracy_score(y_val, y_pred)),
                "precision": float(precision_score(y_val, y_pred, zero_division=0)),
                "recall": float(recall_score(y_val, y_pred, zero_division=0)),
                "f1_score": float(f1_score(y_val, y_pred, zero_division=0)),
                "training_samples": len(X_train),
                "validation_samples": len(X_val),
            }
        except Exception as e:
            logger.error(f"Training failed: {e}")
            return {"error": str(e)}
