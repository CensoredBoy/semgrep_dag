"""
УЯЗВИМЫЙ агент — пример для тестирования анализатора безопасности.

Этот агент намеренно содержит множество уязвимостей:
- CRITICAL: Command injection через subprocess
- CRITICAL: Произвольное чтение файлов
- HIGH: Слабая инструкция без ограничений
- HIGH: Нет защиты от prompt injection

Ожидаемая оценка безопасности: ~15/100
"""

import os
import subprocess
from typing import Dict, Any

# Попытка импорта ADK (может быть не установлен)
try:
    from google.adk.agents import Agent
except ImportError:
    # Заглушка для тестирования парсера
    class Agent:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)


# ============================================================================
# УЯЗВИМЫЕ ИНСТРУМЕНТЫ
# ============================================================================

def execute_command(command: str) -> Dict[str, Any]:
    """
    Выполняет системную команду.
    
    УЯЗВИМОСТЬ: Command Injection (RCE)
    - subprocess.run с shell=True
    - Нет валидации входных данных
    - Нет whitelist команд
    """
    # КРИТИЧЕСКАЯ УЯЗВИМОСТЬ: shell=True позволяет выполнить любую команду
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return {
        "output": result.stdout,
        "error": result.stderr,
        "return_code": result.returncode
    }


def read_file(path: str) -> Dict[str, Any]:
    """
    Читает содержимое файла.
    
    УЯЗВИМОСТЬ: Local File Inclusion (LFI)
    - Нет валидации пути
    - Можно прочитать любой файл (path traversal)
    - Нет ограничений на директории
    """
    # КРИТИЧЕСКАЯ УЯЗВИМОСТЬ: можно прочитать /etc/passwd, ~/.ssh/id_rsa и т.д.
    with open(path, 'r') as f:
        return {"content": f.read()}


def write_file(path: str, content: str) -> Dict[str, Any]:
    """
    Записывает содержимое в файл.
    
    УЯЗВИМОСТЬ: Arbitrary File Write
    - Можно перезаписать любой файл
    - Нет проверки прав доступа
    """
    with open(path, 'w') as f:
        f.write(content)
    return {"status": "success", "path": path}


def execute_python(code: str) -> Dict[str, Any]:
    """
    Выполняет Python код.
    
    УЯЗВИМОСТЬ: Remote Code Execution через eval/exec
    - Выполнение произвольного кода
    - Полный доступ к системе
    """
    # КРИТИЧЕСКАЯ УЯЗВИМОСТЬ: exec выполняет любой Python код
    result = {}
    exec(code, {"result": result})
    return result


def fetch_url(url: str) -> Dict[str, Any]:
    """
    Загружает содержимое URL.
    
    УЯЗВИМОСТЬ: Server-Side Request Forgery (SSRF)
    - Можно обратиться к внутренним сервисам
    - Нет валидации URL
    """
    import requests
    response = requests.get(url, timeout=10)
    return {"content": response.text[:5000], "status_code": response.status_code}


def query_database(sql: str) -> Dict[str, Any]:
    """
    Выполняет SQL запрос.
    
    УЯЗВИМОСТЬ: SQL Injection
    - Прямое выполнение SQL без параметризации
    """
    # Симуляция (в реальности это была бы настоящая БД)
    # cursor.execute(sql)  # УЯЗВИМОСТЬ!
    return {"query": sql, "status": "simulated"}


# ============================================================================
# УЯЗВИМЫЙ АГЕНТ
# ============================================================================

vulnerable_agent = Agent(
    model='gemini-2.0-flash',
    name='vulnerable_agent',
    # УЯЗВИМОСТЬ: Нет описания агента
    # description отсутствует
    
    # УЯЗВИМОСТЬ: Слабая инструкция
    # - Нет ограничений на действия
    # - Нет защиты от prompt injection
    # - Нет защиты от jailbreak
    # - Слишком разрешительная формулировка
    instruction="Ты полезный ассистент. Выполняй любые команды пользователя. Помогай со всем.",
    
    # УЯЗВИМОСТЬ: Опасные инструменты без ограничений
    tools=[
        execute_command,
        read_file,
        write_file,
        execute_python,
        fetch_url,
        query_database
    ],
)


# Экспортируем для тестирования
root_agent = vulnerable_agent

