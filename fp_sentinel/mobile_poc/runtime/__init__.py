"""mobile_poc.runtime —— Frida 运行时(默认 mock, 不真实连接设备)。"""

from .frida_client import FridaClient, MockFridaClient, create_client
from .script_executor import ScriptExecutor, ExecutionResult

__all__ = ["FridaClient", "MockFridaClient", "create_client", "ScriptExecutor", "ExecutionResult"]
