"""
攻击链动态风险评分

结合 CVSS、EPSS、资产价值、可达性等多维度进行综合评分
"""

import logging
from typing import Dict, Any, List
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class AssetContext:
    """资产上下文"""
    data_sensitivity: float = 0.5    # 数据敏感度 0-1
    user_count: int = 1000           # 用户数量
    compliance_factor: float = 1.0   # 合规因子
    network_exposure: str = "internal"  # internal/dmz/public
    has_waf: bool = False
    has_ids: bool = False


@dataclass
class RiskScore:
    """风险评分"""
    technical_risk: float      # 技术风险
    reachability: float        # 可达性
    asset_value: float         # 资产价值
    detection_difficulty: float  # 检测难度
    overall_score: float       # 综合评分
    severity: str              # 严重级别
    cvss: float                # CVSS分数
    epss: float                # EPSS概率
    details: Dict[str, Any] = field(default_factory=dict)


class ChainRiskScorer:
    """攻击链风险动态评分器"""

    # 默认 CVSS 分数映射
    DEFAULT_CVSS = {
        "CRITICAL": 9.5,
        "HIGH": 7.5,
        "MEDIUM": 5.0,
        "LOW": 2.5,
        "INFO": 0.5,
    }

    # 默认 EPSS 分数映射
    DEFAULT_EPSS = {
        "sql_injection": 0.85,
        "command_injection": 0.90,
        "eval": 0.80,
        "xss": 0.65,
        "ssrf": 0.70,
        "path_traversal": 0.60,
        "deserialization": 0.75,
        "prompt_injection": 0.40,
        "prototype_pollution": 0.50,
    }

    # 网络暴露系数
    NETWORK_EXPOSURE_FACTOR = {
        "internal": 0.3,
        "dmz": 0.6,
        "public": 1.0,
    }

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.cvss_overrides: Dict[str, float] = {}
        self.epss_overrides: Dict[str, float] = {}

    def score(
        self,
        chain: Any,
        context: AssetContext = None,
    ) -> RiskScore:
        """
        计算攻击链风险评分

        评分公式:
        技术风险 = max(CVSS) * EPSS * exploit_available
        可达性 = network_reachability * auth_bypass_factor
        资产价值 = data_sensitivity * log(user_count) * compliance_factor
        检测难度 = 1 / (rule_coverage * log_completeness)

        综合 = 技术风险 * 0.4 + 可达性 * 0.2 + 资产价值 * 0.2 + 检测难度 * 0.2
        """
        if context is None:
            context = AssetContext()

        # 获取步骤信息
        steps = getattr(chain, 'steps', [])
        if not steps:
            return self._default_score()

        # 1. 技术风险
        cvss = self._calculate_cvss(steps)
        epss = self._calculate_epss(steps)
        exploit_available = self._check_exploit_available(steps)
        technical_risk = cvss / 10.0 * epss * exploit_available

        # 2. 可达性
        network_factor = self.NETWORK_EXPOSURE_FACTOR.get(
            context.network_exposure, 0.5
        )
        auth_bypass = self._calculate_auth_bypass_factor(steps)
        reachability = network_factor * auth_bypass
        if context.has_waf:
            reachability *= 0.7
        if context.has_ids:
            reachability *= 0.8

        # 3. 资产价值
        import math
        user_factor = min(1.0, math.log10(max(1, context.user_count)) / 6)
        asset_value = (
            context.data_sensitivity * 0.5
            + user_factor * 0.3
            + context.compliance_factor * 0.2
        )

        # 4. 检测难度
        rule_coverage = self._estimate_rule_coverage(steps)
        log_completeness = 0.7  # 默认日志完整度
        detection_difficulty = 1.0 / max(0.1, rule_coverage * log_completeness)

        # 综合评分
        overall = (
            technical_risk * 0.4
            + reachability * 0.2
            + asset_value * 0.2
            + min(1.0, detection_difficulty) * 0.2
        )

        # 推断严重级别
        severity = self._infer_severity(overall)

        return RiskScore(
            technical_risk=round(technical_risk, 4),
            reachability=round(reachability, 4),
            asset_value=round(asset_value, 4),
            detection_difficulty=round(min(1.0, detection_difficulty), 4),
            overall_score=round(min(1.0, overall), 4),
            severity=severity,
            cvss=cvss,
            epss=epss,
            details={
                "network_factor": network_factor,
                "auth_bypass": auth_bypass,
                "user_factor": user_factor,
                "rule_coverage": rule_coverage,
            },
        )

    def _calculate_cvss(self, steps: List[Any]) -> float:
        """计算CVSS分数（取最大值）"""
        max_cvss = 0.0
        for step in steps:
            node = getattr(step, 'node', None)
            rule_id = getattr(node, 'rule_id', '') if node else ''
            severity = getattr(node, 'severity', 'MEDIUM') if node else 'MEDIUM'

            # 优先使用覆盖值
            if rule_id in self.cvss_overrides:
                cvss = self.cvss_overrides[rule_id]
            else:
                cvss = self.DEFAULT_CVSS.get(severity, 5.0)

            max_cvss = max(max_cvss, cvss)

        return max_cvss

    def _calculate_epss(self, steps: List[Any]) -> float:
        """计算EPSS概率（取最大值）"""
        max_epss = 0.0
        for step in steps:
            node = getattr(step, 'node', None)
            rule_id = getattr(node, 'rule_id', '') if node else ''

            if rule_id in self.epss_overrides:
                epss = self.epss_overrides[rule_id]
            else:
                # 从规则ID推断
                epss = 0.3  # 默认
                for key, val in self.DEFAULT_EPSS.items():
                    if key in rule_id.lower():
                        epss = val
                        break

            max_epss = max(max_epss, epss)

        return max_epss

    def _check_exploit_available(self, steps: List[Any]) -> float:
        """检查是否有可用的exploit"""
        # 简化：根据漏洞类型推断
        for step in steps:
            node = getattr(step, 'node', None)
            rule_id = getattr(node, 'rule_id', '') if node else ''

            high_exploit = [
                "sql_injection", "command_injection", "eval",
                "deserialization", "path_traversal",
            ]
            for keyword in high_exploit:
                if keyword in rule_id.lower():
                    return 0.9

        return 0.5

    def _calculate_auth_bypass_factor(self, steps: List[Any]) -> float:
        """计算认证绕过因子"""
        auth_steps = [s for s in steps if "auth" in getattr(
            getattr(s, 'node', None), 'rule_id', ''
        ).lower()]

        if auth_steps:
            return 0.9  # 有认证相关漏洞，绕过概率高
        return 0.5

    def _estimate_rule_coverage(self, steps: List[Any]) -> float:
        """估计规则覆盖率"""
        if not steps:
            return 0.5

        covered = sum(1 for s in steps if getattr(s, 'node', None))
        return covered / len(steps)

    def _infer_severity(self, score: float) -> str:
        if score >= 0.8:
            return "CRITICAL"
        elif score >= 0.6:
            return "HIGH"
        elif score >= 0.4:
            return "MEDIUM"
        elif score >= 0.2:
            return "LOW"
        return "INFO"

    def _default_score(self) -> RiskScore:
        return RiskScore(
            technical_risk=0.0, reachability=0.0, asset_value=0.0,
            detection_difficulty=0.0, overall_score=0.0,
            severity="INFO", cvss=0.0, epss=0.0,
        )
