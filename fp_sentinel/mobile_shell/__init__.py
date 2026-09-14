"""
玄鉴 v4.0 mobile_shell —— 砸壳引擎包（能力①）

能力：加固类型识别 + Android/iOS 脱壳（frida 优先，静态降级）。
安全红线：S1（仅 localhost）、S3（无删除 API）、subprocess 全部 shell=False。
"""

from fp_sentinel.mobile_shell.core.android_dumper import AndroidDumper  # noqa: F401
from fp_sentinel.mobile_shell.core.base import (  # noqa: F401
    ShellEngine,
    UnsafeTargetError,
    assert_local,
)
from fp_sentinel.mobile_shell.core.detection import ProtectionDetector  # noqa: F401
from fp_sentinel.mobile_shell.core.ios_dumper import IOSDumper  # noqa: F401

__version__ = "4.0.0"
