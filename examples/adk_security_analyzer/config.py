"""
Конфигурация и паттерны для анализа безопасности ADK агентов.
"""

from typing import Dict, List
from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    """Уровни критичности уязвимостей."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Vulnerability:
    """Найденная уязвимость."""
    id: str
    category: str
    severity: Severity
    title: str
    description: str
    location: str
    recommendation: str


@dataclass
class SecurityReport:
    """Отчёт о безопасности агента."""
    agent_name: str
    total_score: int
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    instruction_score: int = 0
    tool_score: int = 0
    validation_score: int = 0
    best_practices_score: int = 0


# Опасные паттерны в коде инструментов
DANGEROUS_PATTERNS = {
    "subprocess": {
        "pattern": r"subprocess\.(run|call|Popen|check_output)",
        "severity": Severity.CRITICAL,
        "description": "Выполнение системных команд",
        "recommendation": "Избегайте subprocess или используйте whitelist команд"
    },
    "shell_true": {
        "pattern": r"shell\s*=\s*True",
        "severity": Severity.CRITICAL,
        "description": "Использование shell=True позволяет command injection",
        "recommendation": "Используйте shell=False и передавайте аргументы списком"
    },
    "os_system": {
        "pattern": r"os\.system\s*\(",
        "severity": Severity.CRITICAL,
        "description": "Выполнение команд через os.system",
        "recommendation": "Используйте subprocess с валидацией входных данных"
    },
    "eval": {
        "pattern": r"\beval\s*\(",
        "severity": Severity.CRITICAL,
        "description": "Выполнение произвольного Python кода",
        "recommendation": "Никогда не используйте eval с пользовательским вводом"
    },
    "exec": {
        "pattern": r"\bexec\s*\(",
        "severity": Severity.CRITICAL,
        "description": "Выполнение произвольного Python кода",
        "recommendation": "Никогда не используйте exec с пользовательским вводом"
    },
    "open_file": {
        "pattern": r"\bopen\s*\([^)]*\)",
        "severity": Severity.HIGH,
        "description": "Операции с файловой системой",
        "recommendation": "Валидируйте пути файлов и используйте whitelist"
    },
    "requests_get": {
        "pattern": r"requests\.(get|post|put|delete|patch)\s*\(",
        "severity": Severity.MEDIUM,
        "description": "HTTP запросы могут привести к SSRF",
        "recommendation": "Валидируйте URL и используйте whitelist доменов"
    },
    "sql_query": {
        "pattern": r"(execute|cursor\.execute|\.query)\s*\([^)]*\%|f['\"].*SELECT|f['\"].*INSERT|f['\"].*UPDATE|f['\"].*DELETE",
        "severity": Severity.HIGH,
        "description": "Потенциальная SQL injection",
        "recommendation": "Используйте параметризованные запросы"
    },
    "pickle": {
        "pattern": r"pickle\.(load|loads)\s*\(",
        "severity": Severity.HIGH,
        "description": "Десериализация pickle может выполнить произвольный код",
        "recommendation": "Избегайте pickle для ненадёжных данных"
    },
    "yaml_load": {
        "pattern": r"yaml\.load\s*\([^)]*\)(?!\s*,\s*Loader\s*=\s*yaml\.SafeLoader)",
        "severity": Severity.HIGH,
        "description": "yaml.load без SafeLoader может выполнить произвольный код",
        "recommendation": "Используйте yaml.safe_load или yaml.load с SafeLoader"
    }
}

# Паттерны слабых инструкций (уязвимость к jailbreak)
WEAK_INSTRUCTION_PATTERNS = {
    "no_restrictions": {
        "pattern": r"^.{0,100}$",  # Слишком короткая инструкция
        "severity": Severity.HIGH,
        "description": "Слишком короткая инструкция без явных ограничений",
        "recommendation": "Добавьте явные разрешённые и запрещённые действия"
    },
    "permissive_any": {
        "patterns": [
            r"выполняй\s+любые",
            r"делай\s+(всё|все|что\s+угодно)",
            r"do\s+anything",
            r"execute\s+any",
            r"помогай?\s+со?\s+всем"
        ],
        "severity": Severity.HIGH,
        "description": "Слишком разрешительная формулировка",
        "recommendation": "Ограничьте scope действий агента"
    }
}

# Паттерны защиты от prompt injection (их ОТСУТСТВИЕ — уязвимость)
INJECTION_PROTECTION_PATTERNS = [
    r"игнор(ируй|ировать)\s+(эти\s+)?инструкции",
    r"ignore\s+(these\s+)?instructions",
    r"запрещ(ено|ённые|ается)",
    r"forbidden",
    r"не\s+выполняй",
    r"do\s+not\s+(execute|perform|follow)",
    r"защит[аы]\s+от\s+атак",
    r"подозрительн(ый|ые|ых)\s+запрос",
    r"suspicious\s+request"
]

# Паттерны хороших практик
BEST_PRACTICES = {
    "has_description": {
        "check": "description",
        "severity": Severity.LOW,
        "description": "Агент должен иметь описание для multi-agent сценариев"
    },
    "has_allowed_actions": {
        "patterns": [r"разрешённые\s+действия", r"allowed\s+actions", r"можешь\s+только"],
        "severity": Severity.MEDIUM,
        "description": "Инструкция должна явно указывать разрешённые действия"
    },
    "has_forbidden_actions": {
        "patterns": [r"запрещённые\s+действия", r"forbidden\s+actions", r"нельзя", r"не\s+должен"],
        "severity": Severity.MEDIUM,
        "description": "Инструкция должна явно указывать запрещённые действия"
    }
}

# Веса для расчёта общей оценки
SCORE_WEIGHTS = {
    "instruction": 30,  # Максимум 30 баллов за инструкции
    "tools": 40,        # Максимум 40 баллов за безопасность инструментов
    "validation": 15,   # Максимум 15 баллов за валидацию входных данных
    "best_practices": 15  # Максимум 15 баллов за лучшие практики
}

# Штрафы за уязвимости
SEVERITY_PENALTIES = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0
}

