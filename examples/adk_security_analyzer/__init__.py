"""
ADK Security Analyzer - агент для анализа безопасности других ADK агентов.

Этот модуль предоставляет инструменты для статического анализа исходного кода
агентов Google ADK и выявления потенциальных уязвимостей:
- Tool Abuse (небезопасное использование инструментов)
- Jailbreak (слабые инструкции)
- Prompt Injection (уязвимость к внедрению инструкций)
- System Prompt Leakage (риск раскрытия системного промпта)
"""

from .agent import security_analyzer_agent

__version__ = "1.0.0"
__all__ = ["security_analyzer_agent"]

