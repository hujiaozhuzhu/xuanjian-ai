"""
扫描器基类

定义所有扫描器的通用接口
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from ..models import ScanResult, ScanTool


class BaseScanner(ABC):
    """扫描器基类"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)

    @abstractmethod
    async def scan(self, target_path: str, **kwargs) -> List[ScanResult]:
        """
        扫描目标路径

        Args:
            target_path: 目标路径
            **kwargs: 额外参数

        Returns:
            List[ScanResult]: 扫描结果列表
        """
        pass

    @abstractmethod
    def get_tool_type(self) -> ScanTool:
        """获取扫描工具类型"""
        pass

    def _generate_id(self, tool: str, rule_id: str, file: str, line: int) -> str:
        """生成结果唯一ID"""
        return f"{tool}:{rule_id}:{file}:{line}"
