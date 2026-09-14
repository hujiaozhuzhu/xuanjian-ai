"""mobile_poc.models —— POC 结果数据模型。"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

__all__ = ["POCResult", "ValidationReport"]


@dataclass
class ValidationReport:
    """POC 校验结果(由 core.validator.POCValidator 产出)。"""

    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    checks: Dict[str, bool] = field(default_factory=dict)
    score: float = 0.0  # 0-100

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": self.errors,
            "warnings": self.warnings,
            "checks": self.checks,
            "score": self.score,
        }


@dataclass
class POCResult:
    """单次 POC 生成结果。"""

    success: bool
    template: str                       # 模板相对名, 如 java/basic_hook.js.tmpl
    goal: str                           # 生成意图, 如 plaintext-capture
    language: str                       # js / py
    script: str = ""                    # 渲染后的脚本全文
    script_path: Optional[str] = None   # 落盘路径(未落盘为 None)
    platform: str = "android"           # android / ios
    package_name: Optional[str] = None
    validation: Optional[ValidationReport] = None
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "template": self.template,
            "goal": self.goal,
            "language": self.language,
            "script_length": len(self.script),
            "script_path": self.script_path,
            "platform": self.platform,
            "package_name": self.package_name,
            "validation": self.validation.to_dict() if self.validation else None,
            "warnings": self.warnings,
            "metadata": self.metadata,
            "generated_at": self.generated_at,
        }

    def save(self, output_dir: str, filename: Optional[str] = None) -> str:
        """将脚本写入本地文件, 返回绝对路径。"""
        from pathlib import Path

        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        if filename is None:
            stem = self.template.replace("/", "_").rsplit(".", 2)[0]
            filename = f"{stem}.{self.language}"
        path = out_dir / filename
        path.write_text(self.script, encoding="utf-8")
        self.script_path = str(path.resolve())
        return self.script_path
