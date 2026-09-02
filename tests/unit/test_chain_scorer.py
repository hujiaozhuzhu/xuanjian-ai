"""
攻击链评分单元测试

覆盖 CVSS/EPSS 权重计算、可达性因子、资产价值映射
"""

import pytest
from fp_sentinel.analysis.chain_scorer import (
    ChainRiskScorer,
    AssetContext,
    RiskScore,
)


class TestChainRiskScorer:
    """攻击链评分测试"""

    def setup_method(self):
        self.scorer = ChainRiskScorer()

    def test_score_basic(self):
        """基本评分"""
        chain = type('Chain', (), {
            'steps': [
                type('Step', (), {
                    'node': type('Node', (), {
                        'rule_id': 'js.injection.eval',
                        'severity': 'CRITICAL',
                    })(),
                    'difficulty': 'EASY',
                    'exploitability': 0.9,
                })(),
            ],
        })()

        risk = self.scorer.score(chain)
        assert risk.overall_score > 0
        assert risk.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

    def test_score_with_context(self):
        """带资产上下文的评分"""
        chain = type('Chain', (), {
            'steps': [
                type('Step', (), {
                    'node': type('Node', (), {
                        'rule_id': 'js.node.sql-injection',
                        'severity': 'CRITICAL',
                    })(),
                })(),
            ],
        })()

        context = AssetContext(
            data_sensitivity=0.9,
            user_count=100000,
            network_exposure="public",
        )

        risk = self.scorer.score(chain, context)
        assert risk.asset_value > 0.5
        assert risk.reachability > 0.3

    def test_score_with_waf(self):
        """有WAF时可达性应降低"""
        chain = type('Chain', (), {
            'steps': [
                type('Step', (), {
                    'node': type('Node', (), {
                        'rule_id': 'js.xss.innerhtml',
                        'severity': 'HIGH',
                    })(),
                })(),
            ],
        })()

        context_no_waf = AssetContext(has_waf=False)
        context_with_waf = AssetContext(has_waf=True)

        risk_no_waf = self.scorer.score(chain, context_no_waf)
        risk_with_waf = self.scorer.score(chain, context_with_waf)

        assert risk_no_waf.reachability >= risk_with_waf.reachability

    def test_score_empty_chain(self):
        """空链评分"""
        chain = type('Chain', (), {'steps': []})()
        risk = self.scorer.score(chain)
        assert risk.overall_score == 0.0

    def test_severity_mapping(self):
        """严重级别映射"""
        assert self.scorer._infer_severity(0.9) == "CRITICAL"
        assert self.scorer._infer_severity(0.7) == "HIGH"
        assert self.scorer._infer_severity(0.5) == "MEDIUM"
        assert self.scorer._infer_severity(0.3) == "LOW"
        assert self.scorer._infer_severity(0.1) == "INFO"

    def test_cvss_calculation(self):
        """CVSS 计算"""
        steps = [
            type('Step', (), {
                'node': type('Node', (), {
                    'rule_id': 'js.injection.eval',
                    'severity': 'CRITICAL',
                })(),
            })(),
        ]
        cvss = self.scorer._calculate_cvss(steps)
        assert cvss >= 9.0

    def test_epss_mapping(self):
        """EPSS 映射"""
        steps = [
            type('Step', (), {
                'node': type('Node', (), {
                    'rule_id': 'js.node.sql-injection',
                })(),
            })(),
        ]
        epss = self.scorer._calculate_epss(steps)
        assert epss >= 0.3  # 默认值或匹配值

    def test_network_exposure_factor(self):
        """网络暴露因子"""
        assert self.scorer.NETWORK_EXPOSURE_FACTOR["public"] > \
               self.scorer.NETWORK_EXPOSURE_FACTOR["internal"]
