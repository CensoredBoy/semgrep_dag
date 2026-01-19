"""
Анализатор безопасности инструментов (tools) агентов.

Проверяет:
- Опасные операции (file system, network, shell execution)
- Отсутствие валидации входных данных
- Избыточные привилегии
- Отсутствие rate limiting и логирования
"""

import re
from typing import Dict, List, Any, Optional

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import (
    Severity,
    DANGEROUS_PATTERNS,
    SCORE_WEIGHTS,
    SEVERITY_PENALTIES
)


def analyze_tools(
    tools: List[Dict[str, Any]],
    agent_name: str = "unknown"
) -> Dict[str, Any]:
    """
    Анализирует инструменты агента на предмет уязвимостей.
    
    Args:
        tools: Список инструментов с полями name, source_code, parameters.
        agent_name: Имя агента для отчёта.
        
    Returns:
        Словарь с результатами анализа:
        - vulnerabilities: список найденных уязвимостей
        - score: оценка безопасности инструментов (0-40)
        - dangerous_tools: список опасных инструментов
        - recommendations: рекомендации по улучшению
    """
    result = {
        "status": "success",
        "agent_name": agent_name,
        "vulnerabilities": [],
        "score": SCORE_WEIGHTS["tools"],  # Начинаем с максимума
        "dangerous_tools": [],
        "safe_tools": [],
        "recommendations": [],
        "validation_score": SCORE_WEIGHTS["validation"]
    }
    
    if not tools:
        # Нет инструментов — это может быть и хорошо (простой агент)
        result["recommendations"].append(
            "Агент не имеет инструментов. Убедитесь, что это соответствует его назначению."
        )
        return result
    
    vuln_counter = 1
    
    for tool in tools:
        tool_name = tool.get("name", "unknown_tool")
        source_code = tool.get("source_code", "")
        parameters = tool.get("parameters", [])
        line_number = tool.get("line_number", 0)
        
        tool_vulnerabilities = []
        is_dangerous = False
        
        # Проверка 1: Опасные паттерны в коде
        for pattern_name, pattern_info in DANGEROUS_PATTERNS.items():
            pattern = pattern_info["pattern"]
            if re.search(pattern, source_code, re.IGNORECASE | re.MULTILINE):
                severity = pattern_info["severity"]
                is_dangerous = True
                
                vuln = {
                    "id": f"TOOL-{vuln_counter:03d}",
                    "category": "tool_abuse",
                    "severity": severity.value,
                    "title": f"Dangerous Pattern: {pattern_name}",
                    "description": pattern_info["description"],
                    "location": f"{tool_name}() at line {line_number}",
                    "recommendation": pattern_info["recommendation"]
                }
                result["vulnerabilities"].append(vuln)
                tool_vulnerabilities.append(vuln)
                result["score"] -= SEVERITY_PENALTIES[severity]
                vuln_counter += 1
        
        # Проверка 2: Валидация входных данных
        has_validation = _check_input_validation(source_code, parameters)
        if not has_validation and parameters:
            # Есть параметры, но нет валидации
            vuln = {
                "id": f"TOOL-{vuln_counter:03d}",
                "category": "tool_abuse",
                "severity": Severity.MEDIUM.value,
                "title": "Missing Input Validation",
                "description": f"Функция {tool_name}() не валидирует входные параметры: {', '.join(parameters)}",
                "location": f"{tool_name}() at line {line_number}",
                "recommendation": "Добавьте проверку типов и значений входных параметров"
            }
            result["vulnerabilities"].append(vuln)
            tool_vulnerabilities.append(vuln)
            result["validation_score"] -= 5
            vuln_counter += 1
        
        # Проверка 3: Whitelist проверки
        has_whitelist = _check_whitelist_validation(source_code)
        if not has_whitelist and _is_sensitive_operation(source_code):
            vuln = {
                "id": f"TOOL-{vuln_counter:03d}",
                "category": "tool_abuse",
                "severity": Severity.MEDIUM.value,
                "title": "Missing Whitelist Validation",
                "description": f"Функция {tool_name}() выполняет чувствительные операции без whitelist проверки",
                "location": f"{tool_name}() at line {line_number}",
                "recommendation": "Используйте whitelist для ограничения допустимых значений"
            }
            result["vulnerabilities"].append(vuln)
            tool_vulnerabilities.append(vuln)
            result["score"] -= SEVERITY_PENALTIES[Severity.MEDIUM]
            vuln_counter += 1
        
        # Проверка 4: Error handling
        has_error_handling = _check_error_handling(source_code)
        if not has_error_handling and _is_external_operation(source_code):
            vuln = {
                "id": f"TOOL-{vuln_counter:03d}",
                "category": "best_practices",
                "severity": Severity.LOW.value,
                "title": "Missing Error Handling",
                "description": f"Функция {tool_name}() не обрабатывает ошибки для внешних операций",
                "location": f"{tool_name}() at line {line_number}",
                "recommendation": "Добавьте try/except для обработки ошибок"
            }
            result["vulnerabilities"].append(vuln)
            tool_vulnerabilities.append(vuln)
            result["score"] -= SEVERITY_PENALTIES[Severity.LOW]
            vuln_counter += 1
        
        # Классификация инструмента
        if is_dangerous:
            result["dangerous_tools"].append({
                "name": tool_name,
                "vulnerabilities": len(tool_vulnerabilities),
                "line_number": line_number
            })
        else:
            result["safe_tools"].append({
                "name": tool_name,
                "has_validation": has_validation,
                "has_whitelist": has_whitelist,
                "line_number": line_number
            })
    
    # Убеждаемся, что score не отрицательный
    result["score"] = max(0, result["score"])
    result["validation_score"] = max(0, result["validation_score"])
    
    # Формируем рекомендации
    if result["dangerous_tools"]:
        dangerous_names = [t["name"] for t in result["dangerous_tools"]]
        result["recommendations"].append(
            f"Опасные инструменты требуют особого внимания: {', '.join(dangerous_names)}"
        )
        result["recommendations"].append(
            "Рассмотрите использование before_tool_callback для дополнительной валидации"
        )
    
    return result


def _check_input_validation(source_code: str, parameters: List[str]) -> bool:
    """Проверяет наличие валидации входных данных."""
    validation_patterns = [
        r"if\s+not\s+\w+:",
        r"isinstance\s*\(",
        r"if\s+\w+\s*(is\s+None|==\s*None|!=\s*None)",
        r"if\s+not\s+isinstance",
        r"raise\s+(ValueError|TypeError|ValidationError)",
        r"\.strip\(\)",
        r"len\s*\(\s*\w+\s*\)",
        r"if\s+len\s*\(",
        r"validate",
        r"assert\s+",
        r"return\s+\{\s*['\"]error['\"]\s*:"
    ]
    
    for pattern in validation_patterns:
        if re.search(pattern, source_code, re.IGNORECASE):
            return True
    
    return False


def _check_whitelist_validation(source_code: str) -> bool:
    """Проверяет наличие whitelist проверки."""
    whitelist_patterns = [
        r"(allowed|whitelist|valid|permitted)\s*=\s*\[",
        r"(ALLOWED|WHITELIST|VALID|PERMITTED)\s*=",
        r"if\s+\w+\s+(not\s+)?in\s+(allowed|whitelist|valid|permitted|\[)",
        r"if\s+\w+\s+(not\s+)?in\s+[A-Z_]+",
        r"\.lower\(\)\s+(not\s+)?in\s+\[",
        r"not\s+in\s+\w+_list"
    ]
    
    for pattern in whitelist_patterns:
        if re.search(pattern, source_code, re.IGNORECASE):
            return True
    
    return False


def _check_error_handling(source_code: str) -> bool:
    """Проверяет наличие обработки ошибок."""
    error_patterns = [
        r"try\s*:",
        r"except\s+",
        r"raise\s+",
        r"return\s+\{\s*['\"]error['\"]\s*:",
        r"return\s+\{\s*['\"]status['\"]\s*:\s*['\"]error['\"]"
    ]
    
    for pattern in error_patterns:
        if re.search(pattern, source_code, re.IGNORECASE):
            return True
    
    return False


def _is_sensitive_operation(source_code: str) -> bool:
    """Определяет, выполняет ли функция чувствительные операции."""
    sensitive_patterns = [
        r"open\s*\(",
        r"requests\.",
        r"subprocess\.",
        r"os\.(system|popen|exec|remove|rmdir|chmod|chown)",
        r"shutil\.",
        r"socket\.",
        r"\.execute\s*\(",
        r"urllib",
        r"http"
    ]
    
    return any(re.search(p, source_code) for p in sensitive_patterns)


def _is_external_operation(source_code: str) -> bool:
    """Определяет, выполняет ли функция внешние операции."""
    external_patterns = [
        r"requests\.",
        r"urllib",
        r"socket\.",
        r"http",
        r"api",
        r"fetch",
        r"\.connect\(",
        r"\.send\("
    ]
    
    return any(re.search(p, source_code, re.IGNORECASE) for p in external_patterns)


def analyze_single_tool(
    name: str,
    source_code: str,
    parameters: List[str] = None,
    line_number: int = 0
) -> Dict[str, Any]:
    """
    Анализирует один инструмент.
    
    Args:
        name: Имя инструмента.
        source_code: Исходный код функции.
        parameters: Список параметров.
        line_number: Номер строки в файле.
        
    Returns:
        Результат анализа инструмента.
    """
    tool = {
        "name": name,
        "source_code": source_code,
        "parameters": parameters or [],
        "line_number": line_number
    }
    
    return analyze_tools([tool], agent_name="single_tool_analysis")


def get_tools_security_summary(analysis_result: Dict[str, Any]) -> str:
    """
    Формирует текстовое резюме анализа инструментов.
    
    Args:
        analysis_result: Результат функции analyze_tools.
        
    Returns:
        Строка с резюме анализа.
    """
    vulns = analysis_result.get("vulnerabilities", [])
    score = analysis_result.get("score", 0)
    validation_score = analysis_result.get("validation_score", 0)
    
    critical = sum(1 for v in vulns if v["severity"] == "critical")
    high = sum(1 for v in vulns if v["severity"] == "high")
    medium = sum(1 for v in vulns if v["severity"] == "medium")
    low = sum(1 for v in vulns if v["severity"] == "low")
    
    dangerous = analysis_result.get("dangerous_tools", [])
    safe = analysis_result.get("safe_tools", [])
    
    summary = f"""
Tool Security Score: {score}/{SCORE_WEIGHTS['tools']}
Input Validation Score: {validation_score}/{SCORE_WEIGHTS['validation']}

Tools Analyzed: {len(dangerous) + len(safe)}
- Dangerous: {len(dangerous)}
- Safe: {len(safe)}

Vulnerabilities Found: {len(vulns)}
- Critical: {critical}
- High: {high}
- Medium: {medium}
- Low: {low}
"""
    
    if dangerous:
        summary += "\nDangerous Tools:\n"
        for tool in dangerous:
            summary += f"  - {tool['name']} ({tool['vulnerabilities']} vulnerabilities)\n"
    
    if analysis_result.get("recommendations"):
        summary += "\nRecommendations:\n"
        for i, rec in enumerate(analysis_result["recommendations"], 1):
            summary += f"{i}. {rec}\n"
    
    return summary.strip()

