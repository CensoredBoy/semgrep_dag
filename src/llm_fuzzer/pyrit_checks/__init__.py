"""
PyRIT Checks - проверки безопасности на базе PyRIT фреймворка.

PyRIT — это фреймворк, не готовый инструмент. 
Проверки нужно писать самим, используя PyRIT API.

Структура проверки:
1. Наследование от BasePyRITCheck
2. Реализация метода run()
3. Регистрация через декоратор @register_check

Пример:
    from llm_fuzzer.pyrit_checks import BasePyRITCheck, register_check
    
    @register_check("my-check-id")
    class MyCheck(BasePyRITCheck):
        name = "My Security Check"
        category = "custom"
        severity = "high"
        
        async def run(self, target, config):
            # Логика проверки через PyRIT
            ...
"""

from .base import BasePyRITCheck, register_check, get_registered_checks
from .leakage_check import SystemPromptLeakageCheck
from .tool_calls_check import ToolCallsAbuseCheck

__all__ = [
    "BasePyRITCheck",
    "register_check",
    "get_registered_checks",
    "SystemPromptLeakageCheck",
    "ToolCallsAbuseCheck",
]
