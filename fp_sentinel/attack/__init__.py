"""
玄鉴 v2.2.0 攻防审计模块（Agent-Attack 领地）

安全红线（S1/S4）：
- 本模块禁止任何向非 localhost 的网络请求执行路径
- PoC 仅生成字符串（模式 A）或本地 crypto 计算（模式 B），零网络
- 所有生成入口必须经 _assert_local() 守卫，非本地目标抛 UnsafeTargetError
"""

from .poc_templates import (
    PocTemplate,
    PocInstance,
    POC_TEMPLATES,
    UnsafeTargetError,
    assert_local,
    generate_poc,
    list_vuln_types,
    forge_jwt_token,
)
from .exploitability import (
    ExploitabilityResult,
    ReachabilityLevel,
    assess,
    assess_many,
)
from .chain_orchestrator import (
    AttackChainReport,
    ChainPath,
    ChainStep,
    SinglePoint,
    orchestrate,
)
from .target_validator import (
    VerifyStatus,
    VerifyResult,
    docker_available,
    verify,
)

__all__ = [
    "PocTemplate", "PocInstance", "POC_TEMPLATES", "UnsafeTargetError",
    "assert_local", "generate_poc", "list_vuln_types", "forge_jwt_token",
    "ExploitabilityResult", "ReachabilityLevel", "assess", "assess_many",
    "AttackChainReport", "ChainPath", "ChainStep", "SinglePoint", "orchestrate",
    "VerifyStatus", "VerifyResult", "docker_available", "verify",
]
