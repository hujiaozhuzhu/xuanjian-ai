#!/usr/bin/env python3
"""
代码审计误报过滤MCP服务器入口点
"""

import asyncio
import sys
import os

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from code_audit_fp.server import main

if __name__ == "__main__":
    asyncio.run(main())