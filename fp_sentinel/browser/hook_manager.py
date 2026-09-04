"""
Hook 管理器

管理函数 Hook 的注册、配置和状态追踪
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

from ..models import HookConfig

logger = logging.getLogger(__name__)


class HookManager:
    """Hook 管理器"""

    def __init__(self):
        self._hooks: Dict[str, List[HookConfig]] = {}  # session_id -> hooks
        self._hook_results: Dict[str, List[Dict[str, Any]]] = {}  # session_id -> results

    def add_hook(self, session_id: str, config: HookConfig):
        """添加 Hook 配置"""
        if session_id not in self._hooks:
            self._hooks[session_id] = []
        self._hooks[session_id].append(config)
        logger.info(f"Added {config.hook_type.value} hook on {config.target} for session {session_id}")

    def remove_hook(self, session_id: str, target: str):
        """移除 Hook"""
        if session_id in self._hooks:
            self._hooks[session_id] = [
                h for h in self._hooks[session_id] if h.target != target
            ]
            logger.info(f"Removed hook on {target} for session {session_id}")

    def get_hooks(self, session_id: str) -> List[HookConfig]:
        """获取会话的所有 Hook"""
        return self._hooks.get(session_id, [])

    def add_result(self, session_id: str, result: Dict[str, Any]):
        """添加 Hook 捕获的结果"""
        if session_id not in self._hook_results:
            self._hook_results[session_id] = []
        result["timestamp"] = datetime.now().isoformat()
        self._hook_results[session_id].append(result)

    def get_results(
        self,
        session_id: str,
        target: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """获取 Hook 捕获的结果"""
        results = self._hook_results.get(session_id, [])
        if target:
            results = [r for r in results if r.get("target") == target]
        return results[-limit:]

    def clear_results(self, session_id: str):
        """清除结果"""
        self._hook_results[session_id] = []

    def get_captured_keys(self, session_id: str) -> List[Dict[str, Any]]:
        """获取捕获的加密密钥"""
        results = self._hook_results.get(session_id, [])
        return [r for r in results if r.get("type") == "crypto_key"]

    def get_captured_calls(self, session_id: str) -> List[Dict[str, Any]]:
        """获取捕获的函数调用"""
        results = self._hook_results.get(session_id, [])
        return [r for r in results if r.get("type") == "hook_call"]

    def get_statistics(self, session_id: str) -> Dict[str, Any]:
        """获取统计信息"""
        results = self._hook_results.get(session_id, [])
        hooks = self._hooks.get(session_id, [])

        stats = {
            "total_hooks": len(hooks),
            "total_captures": len(results),
            "by_type": {},
            "by_target": {},
        }

        for hook in hooks:
            hook_type = hook.hook_type.value
            stats["by_type"][hook_type] = stats["by_type"].get(hook_type, 0) + 1

        for result in results:
            target = result.get("target", "unknown")
            stats["by_target"][target] = stats["by_target"].get(target, 0) + 1

        return stats

    def cleanup_session(self, session_id: str):
        """清理会话数据"""
        self._hooks.pop(session_id, None)
        self._hook_results.pop(session_id, None)
        logger.info(f"Cleaned up hooks for session {session_id}")
