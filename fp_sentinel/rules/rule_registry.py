"""
注册器：加载 skills 规则文件，暴露闸门校验函数。
"""

import sys
import logging
from pathlib import Path
from typing import NoReturn, Optional, List, Dict, Any

logger = logging.getLogger(__name__)

_DEFAULT_RULES_DIR = (
    Path.home() / ".meituan-catpaw" / "4275287949" / "skills" / "fp_sentinel" / "rules"
)
_AUDIT_LOG = Path.home() / ".fp_sentinel" / "audit_failure.log"
_DEFAULT_ROUTES_YAML = _DEFAULT_RULES_DIR / "01-routing-table.yaml"

_instance: Optional["RuleRegistry"] = None


class RuleRegistry:
    """加载 skills 规则目录并提供闸门校验方法。"""

    def __init__(self, rules_dir: Optional[Path] = None) -> None:
        """初始化注册器，指定规则目录（默认 ~/.meituan-catpaw/.../rules）。"""
        self.rules_dir = rules_dir or _DEFAULT_RULES_DIR
        self.rules: List[Dict[str, Any]] = []

    def load(self) -> None:
        """扫描规则目录，将全部规则文件的内存表示加载到 self.rules。"""
        self.rules = []
        if not self.rules_dir.is_dir():
            logger.warning("规则目录不存在: %s", self.rules_dir)
            return
        for fp in sorted(self.rules_dir.iterdir()):
            if fp.is_file() and not fp.name.startswith("."):
                self.rules.append(
                    {"name": fp.name, "path": str(fp), "size": fp.stat().st_size}
                )
        logger.debug("已加载 %d 个规则文件", len(self.rules))

    def check_scope(self, target_ip: str, whitelist: List[str]) -> bool:
        """scope-boundary: 仅当 target_ip 在白名单内放行。"""
        if whitelist == ["*"]:
            return True
        return target_ip in whitelist

    def require_write_opt_in(
        self, write_requested: bool, has_enable_write: bool, has_auth: bool
    ) -> bool:
        """写操作 opt-in 校验：未请求写则放行，否则需同时满足 enable_write 与 auth。"""
        if not write_requested:
            return True
        return has_enable_write and has_auth

    def fail_closed(self, exception: Exception) -> NoReturn:
        """故障关闭：写入 audit_failure.log 后立即 sys.exit(1)。"""
        _AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        _AUDIT_LOG.write_text(
            f"FAIL_CLOSED: {type(exception).__name__}: {exception}\n",
            encoding="utf-8",
        )
        sys.exit(1)

    def load_routes(self, routes_yaml: Optional[Path] = None) -> Dict[str, Any]:
        """加载 routing-table.yaml 返回 parsed dict。不存在或不可用返回空 dict。"""
        path = routes_yaml or (self.rules_dir / "01-routing-table.yaml")
        if not path.exists():
            return {}
        try:
            import yaml  # type: ignore[import-untyped]
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                return {}
            return data
        except ImportError:
            logger.warning("PyYAML 不可用，路由表加载降级为空")
            return {}
        except yaml.YAMLError as exc:
            logger.warning("路由表 YAML 解析失败: %s", exc)
            return {}


def get_registry() -> RuleRegistry:
    """返回 RuleRegistry 单例。"""
    global _instance
    if _instance is None:
        _instance = RuleRegistry()
    return _instance


def load_routes(routes_yaml: Optional[Path] = None) -> Dict[str, Any]:
    """模块级便捷函数：调用 get_registry().load_routes()。"""
    return get_registry().load_routes(routes_yaml)
