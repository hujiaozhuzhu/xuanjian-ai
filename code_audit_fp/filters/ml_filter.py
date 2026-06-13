"""
L3: 机器学习过滤器

使用机器学习模型评估漏洞真实性，支持：
- 模型训练与推理
- 特征提取
- 置信度评分
"""

import pickle
import numpy as np
from typing import List, Optional, Dict, Any, Tuple
from pathlib import Path
from .base import BaseFilter
from ..models import ScanResult, FilterResult, FilterReason


class MLFilter(BaseFilter):
    """机器学习过滤器"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        初始化ML过滤器
        
        Args:
            config: 配置字典，包含模型路径等配置
        """
        super().__init__(config)
        self.filter_level = "L3"
        
        # 模型配置
        self.model_path = self.config.get("model_path", "models/false_positive_model.pkl")
        self.onnx_model_path = self.config.get("onnx_model_path", "models/false_positive_model.onnx")
        self.confidence_threshold = self.config.get("confidence_threshold", 0.7)
        
        # 特征配置
        self.feature_columns = self.config.get("feature_columns", [
            "rule_confidence",
            "severity_score",
            "code_complexity",
            "data_flow_length",
            "has_security_guards",
            "has_input_validation",
            "is_test_code",
            "file_depth",
            "line_count"
        ])
        
        # 加载模型
        self.model = None
        self.onnx_session = None
        self._load_model()
    
    def _load_model(self):
        """加载机器学习模型"""
        try:
            # 尝试加载ONNX模型
            if Path(self.onnx_model_path).exists():
                import onnxruntime as ort
                self.onnx_session = ort.InferenceSession(self.onnx_model_path)
                print(f"已加载ONNX模型: {self.onnx_model_path}")
                return
            
            # 尝试加载pickle模型
            if Path(self.model_path).exists():
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                print(f"已加载pickle模型: {self.model_path}")
                return
            
            print("未找到预训练模型，将使用默认特征权重")
            
        except Exception as e:
            print(f"加载模型失败: {e}")
            self.model = None
            self.onnx_session = None
    
    async def filter(self, scan_result: ScanResult) -> FilterResult:
        """
        过滤单条扫描结果
        
        Args:
            scan_result: 扫描结果
            
        Returns:
            FilterResult: 过滤结果
        """
        if not self.enabled:
            return self._create_pass_through_result(scan_result)
        
        # 提取特征
        features = await self._extract_features(scan_result)
        
        # 使用模型预测
        is_false_positive, confidence = self._predict(features)
        
        # 生成过滤原因
        reasons = self._generate_reasons(features, is_false_positive, confidence)
        
        return FilterResult(
            original=scan_result,
            is_false_positive=is_false_positive,
            confidence=confidence,
            filter_reasons=reasons,
            risk_score=self._calculate_risk_score(scan_result, is_false_positive, confidence),
            recommendation=self._generate_recommendation(
                scan_result, is_false_positive, confidence, 
                self._calculate_risk_score(scan_result, is_false_positive, confidence)
            )
        )
    
    async def _extract_features(self, scan_result: ScanResult) -> Dict[str, float]:
        """
        提取特征
        
        Args:
            scan_result: 扫描结果
            
        Returns:
            Dict[str, float]: 特征字典
        """
        features = {}
        
        # 规则置信度（基于规则ID的启发式）
        features["rule_confidence"] = self._get_rule_confidence(scan_result.rule_id)
        
        # 严重程度评分
        severity_scores = {
            "ERROR": 1.0,
            "WARNING": 0.6,
            "INFO": 0.3
        }
        features["severity_score"] = severity_scores.get(scan_result.severity.value, 0.5)
        
        # 代码复杂度（简化计算）
        features["code_complexity"] = self._calculate_code_complexity(scan_result.code)
        
        # 数据流长度（从元数据获取或默认值）
        features["data_flow_length"] = scan_result.metadata.get("data_flow_length", 5)
        
        # 是否有安全守卫（从元数据获取或默认值）
        features["has_security_guards"] = float(scan_result.metadata.get("has_security_guards", False))
        
        # 是否有输入验证（从元数据获取或默认值）
        features["has_input_validation"] = float(scan_result.metadata.get("has_input_validation", False))
        
        # 是否为测试代码
        features["is_test_code"] = float(self._is_test_code(scan_result.file))
        
        # 文件路径深度
        features["file_depth"] = len(scan_result.file.split('/'))
        
        # 代码行数（估计）
        features["line_count"] = len(scan_result.code.split('\n'))
        
        return features
    
    def _get_rule_confidence(self, rule_id: str) -> float:
        """
        获取规则置信度
        
        Args:
            rule_id: 规则ID
            
        Returns:
            float: 规则置信度 0-1
        """
        # 基于规则ID的启发式置信度
        # 这里可以根据历史数据进行调整
        high_confidence_rules = [
            "sql-injection",
            "xss",
            "command-injection",
            "path-traversal",
            "code-injection"
        ]
        
        medium_confidence_rules = [
            "hardcoded-password",
            "hardcoded-secret",
            "insecure-random",
            "weak-cipher"
        ]
        
        rule_id_lower = rule_id.lower()
        
        for pattern in high_confidence_rules:
            if pattern in rule_id_lower:
                return 0.9
        
        for pattern in medium_confidence_rules:
            if pattern in rule_id_lower:
                return 0.7
        
        return 0.5  # 默认置信度
    
    def _calculate_code_complexity(self, code: str) -> float:
        """
        计算代码复杂度
        
        Args:
            code: 代码片段
            
        Returns:
            float: 复杂度评分 0-1
        """
        complexity = 0.0
        
        # 控制流语句
        control_keywords = ['if', 'else', 'elif', 'for', 'while', 'switch', 'case', 'try', 'except']
        for keyword in control_keywords:
            complexity += code.count(keyword) * 0.1
        
        # 函数调用
        function_calls = code.count('(')
        complexity += function_calls * 0.05
        
        # 嵌套深度
        lines = code.split('\n')
        max_indent = 0
        for line in lines:
            if line.strip():
                indent = len(line) - len(line.lstrip())
                max_indent = max(max_indent, indent)
        complexity += max_indent / 40  # 每4个空格增加0.1
        
        return min(1.0, complexity)
    
    def _is_test_code(self, file_path: str) -> bool:
        """
        判断是否为测试代码
        
        Args:
            file_path: 文件路径
            
        Returns:
            bool: 是否为测试代码
        """
        test_patterns = [
            "test_", "_test.", "tests/", "test/",
            "spec_", "_spec.", "specs/", "spec/",
            "__tests__", "__test__"
        ]
        
        file_path_lower = file_path.lower()
        for pattern in test_patterns:
            if pattern in file_path_lower:
                return True
        
        return False
    
    def _predict(self, features: Dict[str, float]) -> Tuple[bool, float]:
        """
        使用模型预测
        
        Args:
            features: 特征字典
            
        Returns:
            Tuple[bool, float]: (是否为误报, 置信度)
        """
        # 准备特征向量
        feature_vector = []
        for col in self.feature_columns:
            feature_vector.append(features.get(col, 0.0))
        
        feature_array = np.array([feature_vector], dtype=np.float32)
        
        # 使用ONNX模型
        if self.onnx_session is not None:
            try:
                input_name = self.onnx_session.get_inputs()[0].name
                output_name = self.onnx_session.get_outputs()[0].name
                prediction = self.onnx_session.run([output_name], {input_name: feature_array})[0]
                
                # 假设输出是[概率]或[类别, 概率]
                if len(prediction.shape) == 1:
                    probability = prediction[0]
                else:
                    probability = prediction[0][1]  # 假设第二列是正类概率
                
                is_false_positive = probability > self.confidence_threshold
                return is_false_positive, float(probability)
                
            except Exception as e:
                print(f"ONNX推理失败: {e}")
        
        # 使用sklearn模型
        if self.model is not None:
            try:
                probability = self.model.predict_proba(feature_array)[0][1]
                is_false_positive = probability > self.confidence_threshold
                return is_false_positive, float(probability)
            except Exception as e:
                print(f"sklearn推理失败: {e}")
        
        # 默认：基于规则的简单启发式
        return self._heuristic_predict(features)
    
    def _heuristic_predict(self, features: Dict[str, float]) -> Tuple[bool, float]:
        """
        启发式预测（当没有模型时使用）
        
        Args:
            features: 特征字典
            
        Returns:
            Tuple[bool, float]: (是否为误报, 置信度)
        """
        score = 0.0
        
        # 规则置信度权重
        score += features.get("rule_confidence", 0.5) * 0.3
        
        # 严重程度权重
        score += features.get("severity_score", 0.5) * 0.2
        
        # 安全守卫权重
        if features.get("has_security_guards", 0):
            score += 0.2
        
        # 输入验证权重
        if features.get("has_input_validation", 0):
            score += 0.15
        
        # 测试代码权重
        if features.get("is_test_code", 0):
            score += 0.1
        
        # 代码复杂度权重（复杂度高可能更真实）
        complexity = features.get("code_complexity", 0.5)
        score += (1 - complexity) * 0.05
        
        # 判断是否为误报
        is_false_positive = score < 0.5
        confidence = abs(score - 0.5) * 2  # 转换为0-1的置信度
        
        return is_false_positive, confidence
    
    def _generate_reasons(
        self,
        features: Dict[str, float],
        is_false_positive: bool,
        confidence: float
    ) -> List[FilterReason]:
        """
        生成过滤原因
        
        Args:
            features: 特征字典
            is_false_positive: 是否为误报
            confidence: 置信度
            
        Returns:
            List[FilterReason]: 过滤原因列表
        """
        reasons = []
        
        if is_false_positive:
            # 误报原因
            if features.get("has_security_guards", 0):
                reasons.append(FilterReason(
                    filter_level=self.filter_level,
                    rule_name="ml_security_guards",
                    description="ML模型识别到安全守卫措施",
                    confidence=0.8
                ))
            
            if features.get("has_input_validation", 0):
                reasons.append(FilterReason(
                    filter_level=self.filter_level,
                    rule_name="ml_input_validation",
                    description="ML模型识别到输入验证",
                    confidence=0.7
                ))
            
            if features.get("is_test_code", 0):
                reasons.append(FilterReason(
                    filter_level=self.filter_level,
                    rule_name="ml_test_code",
                    description="ML模型识别为测试代码",
                    confidence=0.6
                ))
            
            if features.get("rule_confidence", 0.5) < 0.6:
                reasons.append(FilterReason(
                    filter_level=self.filter_level,
                    rule_name="ml_low_rule_confidence",
                    description="ML模型认为规则置信度较低",
                    confidence=0.5
                ))
        else:
            # 真实问题原因
            if features.get("severity_score", 0.5) > 0.8:
                reasons.append(FilterReason(
                    filter_level=self.filter_level,
                    rule_name="ml_high_severity",
                    description="ML模型识别为高严重程度问题",
                    confidence=0.9
                ))
            
            if features.get("rule_confidence", 0.5) > 0.8:
                reasons.append(FilterReason(
                    filter_level=self.filter_level,
                    rule_name="ml_high_rule_confidence",
                    description="ML模型认为规则置信度较高",
                    confidence=0.8
                ))
            
            if features.get("code_complexity", 0.5) > 0.7:
                reasons.append(FilterReason(
                    filter_level=self.filter_level,
                    rule_name="ml_high_complexity",
                    description="ML模型识别为复杂代码，需要关注",
                    confidence=0.7
                ))
        
        # 如果没有具体原因，添加通用原因
        if not reasons:
            reasons.append(FilterReason(
                filter_level=self.filter_level,
                rule_name="ml_general_assessment",
                description=f"ML模型综合评估，置信度: {confidence:.2f}",
                confidence=confidence
            ))
        
        return reasons
    
    def _create_pass_through_result(self, scan_result: ScanResult) -> FilterResult:
        """
        创建传递结果
        
        Args:
            scan_result: 扫描结果
            
        Returns:
            FilterResult: 过滤结果
        """
        return FilterResult(
            original=scan_result,
            is_false_positive=False,
            confidence=0.5,
            filter_reasons=[],
            risk_score=self._calculate_risk_score(scan_result, False, 0.5),
            recommendation="ML过滤器未启用或模型未加载"
        )
    
    async def train_model(
        self,
        training_data: List[Dict[str, Any]],
        model_type: str = "random_forest",
        validation_split: float = 0.2
    ) -> Dict[str, Any]:
        """
        训练模型
        
        Args:
            training_data: 训练数据
            model_type: 模型类型
            validation_split: 验证集比例
            
        Returns:
            Dict[str, Any]: 训练结果
        """
        from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
        from sklearn.svm import SVC
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        import pickle
        
        # 准备数据
        X = []
        y = []
        
        for item in training_data:
            features = item.get("features", {})
            feature_vector = []
            for col in self.feature_columns:
                feature_vector.append(features.get(col, 0.0))
            X.append(feature_vector)
            y.append(1 if item.get("is_false_positive", False) else 0)
        
        X = np.array(X)
        y = np.array(y)
        
        # 分割数据集
        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=validation_split, random_state=42
        )
        
        # 选择模型
        if model_type == "random_forest":
            model = RandomForestClassifier(n_estimators=100, random_state=42)
        elif model_type == "gradient_boosting":
            model = GradientBoostingClassifier(n_estimators=100, random_state=42)
        elif model_type == "svm":
            model = SVC(probability=True, random_state=42)
        else:
            raise ValueError(f"不支持的模型类型: {model_type}")
        
        # 训练模型
        model.fit(X_train, y_train)
        
        # 评估模型
        y_pred = model.predict(X_val)
        accuracy = accuracy_score(y_val, y_pred)
        precision = precision_score(y_val, y_pred, zero_division=0)
        recall = recall_score(y_val, y_pred, zero_division=0)
        f1 = f1_score(y_val, y_pred, zero_division=0)
        
        # 保存模型
        model_path = f"models/false_positive_model_{model_type}.pkl"
        Path("models").mkdir(exist_ok=True)
        
        with open(model_path, 'wb') as f:
            pickle.dump(model, f)
        
        # 更新模型
        self.model = model
        self.model_path = model_path
        
        return {
            "model_path": model_path,
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "training_samples": len(X_train),
            "validation_samples": len(X_val)
        }