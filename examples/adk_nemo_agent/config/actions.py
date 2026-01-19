"""
Custom Actions для NeMo Guardrails
===================================
Actions для LiteLLM + Ollama агента
"""

import re
import os
import time
import logging
from typing import Optional
from collections import defaultdict

try:
    from nemoguardrails.actions import action
except ImportError:
    # Fallback если NeMo не установлен
    def action():
        def decorator(func):
            return func
        return decorator

logger = logging.getLogger("guardrails.actions")


# =============================================================================
# TOOL ACCESS CONTROL (RBAC)
# =============================================================================

TOOL_PERMISSIONS = {
    "anonymous": ["calculator", "web_search"],
    "user": ["calculator", "web_search", "read_file"],
    "premium": ["calculator", "web_search", "read_file", "send_email"],
    "admin": ["calculator", "web_search", "read_file", "send_email", "execute_code"],
}


@action()
async def check_tool_permission(tool_name: str, user_role: str = "anonymous") -> bool:
    """Проверка разрешения на использование инструмента."""
    allowed = TOOL_PERMISSIONS.get(user_role, [])
    is_allowed = tool_name in allowed
    
    if not is_allowed:
        logger.warning(f"Tool access denied: {tool_name} for role {user_role}")
    
    return is_allowed


# =============================================================================
# PATH SECURITY
# =============================================================================

ALLOWED_DIRECTORIES = ["/data/documents", "/data/reports", "/tmp"]

FORBIDDEN_PATH_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"/etc/",
    r"/proc/",
    r"C:\\Windows",
]


@action()
async def check_path_safety(file_path: str) -> bool:
    """Проверка безопасности пути к файлу."""
    # Проверка запрещённых паттернов
    for pattern in FORBIDDEN_PATH_PATTERNS:
        if re.search(pattern, file_path, re.IGNORECASE):
            logger.warning(f"Forbidden path pattern: {file_path}")
            return False
    
    # Проверка разрешённых директорий
    normalized = os.path.normpath(file_path)
    is_allowed = any(normalized.startswith(d) for d in ALLOWED_DIRECTORIES)
    
    if not is_allowed:
        logger.warning(f"Path not in allowed directories: {file_path}")
    
    return is_allowed


# =============================================================================
# SENSITIVE DATA FILTERING
# =============================================================================

SENSITIVE_PATTERNS = {
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
    "api_key": r"(?:api[_-]?key|secret|token)[=:\s]+['\"]?[\w-]{20,}['\"]?",
    "password": r"(?:password|passwd|pwd)[=:\s]+['\"]?[^\s'\"]+['\"]?",
}


@action()
async def filter_sensitive_data(text: str) -> str:
    """Фильтрация чувствительных данных."""
    filtered = text
    
    for data_type, pattern in SENSITIVE_PATTERNS.items():
        if re.search(pattern, filtered, re.IGNORECASE):
            filtered = re.sub(
                pattern, 
                f"[{data_type.upper()}_REDACTED]", 
                filtered, 
                flags=re.IGNORECASE
            )
            logger.info(f"Sensitive data redacted: {data_type}")
    
    return filtered


@action()
async def check_contains_sensitive_data(text: str) -> bool:
    """Проверка наличия чувствительных данных."""
    for pattern in SENSITIVE_PATTERNS.values():
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


# =============================================================================
# TOPIC CONTROL
# =============================================================================

FORBIDDEN_TOPICS = ["weapons", "drugs", "violence", "terrorism", "exploitation"]


@action()
async def check_topic_allowed(topic: str) -> bool:
    """Проверка разрешённости темы."""
    topic_lower = topic.lower()
    for forbidden in FORBIDDEN_TOPICS:
        if forbidden in topic_lower:
            logger.warning(f"Forbidden topic: {topic}")
            return False
    return True


# =============================================================================
# ACTION COUNTING
# =============================================================================

_action_counters = {}


@action()
async def get_action_count(session_id: str = "default") -> int:
    """Получение количества действий в сессии."""
    return _action_counters.get(session_id, 0)


@action()
async def increment_action_count(session_id: str = "default") -> int:
    """Увеличение счётчика действий."""
    current = _action_counters.get(session_id, 0)
    _action_counters[session_id] = current + 1
    return _action_counters[session_id]


@action()
async def reset_action_count(session_id: str = "default"):
    """Сброс счётчика действий."""
    _action_counters[session_id] = 0


# =============================================================================
# INJECTION DETECTION
# =============================================================================

INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions?",
    r"forget\s+(all\s+)?your\s+rules?",
    r"you\s+are\s+now\s+(?:DAN|jailbroken)",
    r"developer\s+mode",
    r"\[INST\]",
    r"<<SYS>>",
    r"###\s*System",
]


@action()
async def detect_injection(text: str) -> bool:
    """Обнаружение prompt injection."""
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            logger.warning(f"Injection detected: {pattern}")
            return True
    return False


# =============================================================================
# RATE LIMITING
# =============================================================================

RATE_LIMIT_RPM = 60
_request_timestamps = defaultdict(list)


@action()
async def check_rate_limit(user_id: str = "anonymous") -> bool:
    """Проверка rate limit."""
    current_time = time.time()
    minute_ago = current_time - 60
    
    # Очистка старых записей
    _request_timestamps[user_id] = [
        ts for ts in _request_timestamps[user_id] if ts > minute_ago
    ]
    
    if len(_request_timestamps[user_id]) >= RATE_LIMIT_RPM:
        logger.warning(f"Rate limit exceeded: {user_id}")
        return False
    
    _request_timestamps[user_id].append(current_time)
    return True


# =============================================================================
# LOGGING
# =============================================================================

@action()
async def log_security_event(
    event_type: str,
    message: str,
    user_id: str = "anonymous",
    severity: str = "warning"
):
    """Логирование события безопасности."""
    log_msg = f"[SECURITY] {event_type}: {message} (user: {user_id})"
    
    if severity == "critical":
        logger.critical(log_msg)
    elif severity == "error":
        logger.error(log_msg)
    elif severity == "warning":
        logger.warning(log_msg)
    else:
        logger.info(log_msg)
