"""
Custom Actions для NeMo Guardrails
===================================

Эти actions вызываются из Colang rules для выполнения
проверок безопасности и валидации.
"""

import re
import os
import logging
from typing import Optional
from nemoguardrails.actions import action

logger = logging.getLogger("guardrails.actions")


# =============================================================================
# TOOL ACCESS CONTROL
# =============================================================================

# Матрица доступа: роль -> список разрешённых инструментов
TOOL_PERMISSIONS = {
    "anonymous": ["calculator", "web_search"],
    "user": ["calculator", "web_search", "read_file"],
    "premium": ["calculator", "web_search", "read_file", "send_email"],
    "admin": ["calculator", "web_search", "read_file", "send_email", "execute_code"],
}

@action()
async def check_tool_permission(tool_name: str, user_role: str = "anonymous") -> bool:
    """
    Проверка разрешения на использование инструмента.
    
    Args:
        tool_name: Название инструмента
        user_role: Роль пользователя
        
    Returns:
        True если доступ разрешён
    """
    allowed_tools = TOOL_PERMISSIONS.get(user_role, [])
    is_allowed = tool_name in allowed_tools
    
    logger.info(f"Tool permission check: {tool_name} for role {user_role} -> {is_allowed}")
    
    if not is_allowed:
        logger.warning(f"Unauthorized tool access attempt: {tool_name} by {user_role}")
    
    return is_allowed


# =============================================================================
# PATH SECURITY
# =============================================================================

# Разрешённые директории для чтения файлов
ALLOWED_DIRECTORIES = [
    "/data/documents",
    "/data/reports",
    "/data/public",
]

# Запрещённые паттерны в путях
FORBIDDEN_PATH_PATTERNS = [
    r"\.\./",           # Path traversal
    r"\.\.\\",          # Windows path traversal
    r"/etc/",           # Linux system files
    r"/proc/",          # Linux proc
    r"/sys/",           # Linux sys
    r"C:\\Windows",     # Windows system
    r"C:\\System32",    # Windows system
]

@action()
async def check_path_safety(file_path: str) -> bool:
    """
    Проверка безопасности пути к файлу.
    
    Args:
        file_path: Путь к файлу
        
    Returns:
        True если путь безопасен
    """
    # Нормализация пути
    normalized_path = os.path.normpath(file_path)
    
    # Проверка на запрещённые паттерны
    for pattern in FORBIDDEN_PATH_PATTERNS:
        if re.search(pattern, file_path, re.IGNORECASE):
            logger.warning(f"Forbidden path pattern detected: {file_path}")
            return False
    
    # Проверка что путь в разрешённой директории
    is_in_allowed_dir = any(
        normalized_path.startswith(allowed_dir) 
        for allowed_dir in ALLOWED_DIRECTORIES
    )
    
    if not is_in_allowed_dir:
        logger.warning(f"Path not in allowed directories: {file_path}")
        return False
    
    logger.info(f"Path safety check passed: {file_path}")
    return True


# =============================================================================
# SENSITIVE DATA FILTERING
# =============================================================================

# Паттерны для обнаружения чувствительных данных
SENSITIVE_PATTERNS = {
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "phone": r"\b(?:\+7|8)?[\s-]?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}\b",
    "api_key": r"\b(?:api[_-]?key|apikey|secret|token)[=:\s]+['\"]?[\w-]{20,}['\"]?\b",
    "password": r"\b(?:password|passwd|pwd)[=:\s]+['\"]?[^\s'\"]+['\"]?\b",
    "ip_address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
}

@action()
async def filter_sensitive_data(text: str) -> str:
    """
    Фильтрация чувствительных данных из текста.
    
    Args:
        text: Исходный текст
        
    Returns:
        Текст с замаскированными данными
    """
    filtered_text = text
    
    for data_type, pattern in SENSITIVE_PATTERNS.items():
        matches = re.findall(pattern, filtered_text, re.IGNORECASE)
        if matches:
            logger.warning(f"Sensitive data detected: {data_type} ({len(matches)} occurrences)")
            filtered_text = re.sub(pattern, f"[{data_type.upper()}_REDACTED]", filtered_text, flags=re.IGNORECASE)
    
    return filtered_text


@action()
async def check_contains_sensitive_data(text: str) -> bool:
    """
    Проверка наличия чувствительных данных в тексте.
    
    Args:
        text: Текст для проверки
        
    Returns:
        True если обнаружены чувствительные данные
    """
    for data_type, pattern in SENSITIVE_PATTERNS.items():
        if re.search(pattern, text, re.IGNORECASE):
            logger.warning(f"Sensitive data check: found {data_type}")
            return True
    return False


# =============================================================================
# TOPIC CONTROL
# =============================================================================

# Запрещённые темы
FORBIDDEN_TOPICS = [
    "weapons",
    "drugs",
    "violence",
    "terrorism",
    "exploitation",
    "illegal activities",
]

# Чувствительные темы (требуют disclaimer)
SENSITIVE_TOPICS = [
    "medical",
    "legal",
    "financial",
    "investment",
    "health",
]

@action()
async def check_topic_allowed(topic: str) -> bool:
    """
    Проверка разрешённости темы.
    
    Args:
        topic: Тема для проверки
        
    Returns:
        True если тема разрешена
    """
    topic_lower = topic.lower()
    
    # Проверка на запрещённые темы
    for forbidden in FORBIDDEN_TOPICS:
        if forbidden in topic_lower:
            logger.warning(f"Forbidden topic detected: {topic}")
            return False
    
    logger.info(f"Topic allowed: {topic}")
    return True


@action()
async def is_sensitive_topic(topic: str) -> bool:
    """
    Проверка является ли тема чувствительной.
    
    Args:
        topic: Тема для проверки
        
    Returns:
        True если тема чувствительная
    """
    topic_lower = topic.lower()
    
    for sensitive in SENSITIVE_TOPICS:
        if sensitive in topic_lower:
            return True
    
    return False


# =============================================================================
# ACTION COUNTING (для предотвращения бесконечных циклов)
# =============================================================================

# Хранилище счётчиков действий по сессиям
_action_counters = {}

@action()
async def get_action_count(session_id: str = "default") -> int:
    """
    Получение количества выполненных действий в сессии.
    
    Args:
        session_id: ID сессии
        
    Returns:
        Количество действий
    """
    return _action_counters.get(session_id, 0)


@action()
async def increment_action_count(session_id: str = "default") -> int:
    """
    Увеличение счётчика действий.
    
    Args:
        session_id: ID сессии
        
    Returns:
        Новое значение счётчика
    """
    current = _action_counters.get(session_id, 0)
    _action_counters[session_id] = current + 1
    return _action_counters[session_id]


@action()
async def reset_action_count(session_id: str = "default"):
    """Сброс счётчика действий."""
    _action_counters[session_id] = 0


# =============================================================================
# URL VALIDATION
# =============================================================================

# Whitelist разрешённых доменов
ALLOWED_DOMAINS = [
    "google.com",
    "wikipedia.org",
    "github.com",
    "stackoverflow.com",
]

# Blacklist запрещённых доменов
BLOCKED_DOMAINS = [
    "localhost",
    "127.0.0.1",
    "internal",
    "10.0.0.0/8",
    "192.168.0.0/16",
    "172.16.0.0/12",
]

@action()
async def check_url_allowed(url: str) -> bool:
    """
    Проверка разрешённости URL.
    
    Args:
        url: URL для проверки
        
    Returns:
        True если URL разрешён
    """
    from urllib.parse import urlparse
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Проверка на блокированные домены
        for blocked in BLOCKED_DOMAINS:
            if blocked in domain:
                logger.warning(f"Blocked domain detected: {url}")
                return False
        
        # Если whitelist включён, проверяем наличие в нём
        # (закомментировано для гибкости)
        # if not any(allowed in domain for allowed in ALLOWED_DOMAINS):
        #     return False
        
        return True
        
    except Exception as e:
        logger.error(f"URL parsing error: {e}")
        return False


# =============================================================================
# INJECTION DETECTION
# =============================================================================

# Паттерны для обнаружения инъекций
INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions?",
    r"forget\s+(all\s+)?your\s+rules?",
    r"you\s+are\s+now\s+(?:DAN|jailbroken|unrestricted)",
    r"developer\s+mode",
    r"override\s+(?:your\s+)?(?:rules?|instructions?|programming)",
    r"\[INST\]",
    r"<<SYS>>",
    r"###\s*(?:System|Human|Assistant)",
    r"system\s*:\s*",
    r"<\|im_start\|>",
]

@action()
async def detect_injection(text: str) -> bool:
    """
    Обнаружение попыток prompt injection.
    
    Args:
        text: Текст для проверки
        
    Returns:
        True если обнаружена инъекция
    """
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            logger.warning(f"Injection pattern detected: {pattern}")
            return True
    
    return False


# =============================================================================
# RATE LIMITING
# =============================================================================

import time
from collections import defaultdict

# Rate limit: requests per minute per user
RATE_LIMIT_RPM = 60
_request_timestamps = defaultdict(list)

@action()
async def check_rate_limit(user_id: str = "anonymous") -> bool:
    """
    Проверка rate limit.
    
    Args:
        user_id: ID пользователя
        
    Returns:
        True если лимит не превышен
    """
    current_time = time.time()
    minute_ago = current_time - 60
    
    # Очистка старых записей
    _request_timestamps[user_id] = [
        ts for ts in _request_timestamps[user_id] if ts > minute_ago
    ]
    
    # Проверка лимита
    if len(_request_timestamps[user_id]) >= RATE_LIMIT_RPM:
        logger.warning(f"Rate limit exceeded for user: {user_id}")
        return False
    
    # Добавление текущего запроса
    _request_timestamps[user_id].append(current_time)
    return True


# =============================================================================
# LOGGING ACTION
# =============================================================================

@action()
async def log_security_event(
    event_type: str,
    message: str,
    user_id: str = "anonymous",
    severity: str = "warning"
):
    """
    Логирование события безопасности.
    
    Args:
        event_type: Тип события
        message: Описание
        user_id: ID пользователя
        severity: Уровень важности
    """
    log_message = f"[SECURITY] {event_type}: {message} (user: {user_id})"
    
    if severity == "critical":
        logger.critical(log_message)
    elif severity == "error":
        logger.error(log_message)
    elif severity == "warning":
        logger.warning(log_message)
    else:
        logger.info(log_message)

