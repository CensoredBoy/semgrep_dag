"""
ADK Security Analyzer - агент для анализа безопасности ADK агентов.

Запуск через ADK Web:
    cd examples/adk_security_analyzer
    adk web

Откройте http://localhost:8000
"""

from .agent import root_agent

__all__ = ["root_agent"]
