"""
玄鉴 Web 仪表板模块

提供:
- create_web_app(): 创建独立的 Web 仪表板 FastAPI 应用
- Vue3 + Element Plus 单页面仪表板
- /api/v1/ REST API
- WebSocket 实时推送
"""

from .app import create_web_app

__all__ = ["create_web_app"]
