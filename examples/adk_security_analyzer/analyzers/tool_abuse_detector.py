"""
Детектор уязвимостей к tool abuse атакам.

Анализирует инструменты агента на предмет:
- Опасных операций (shell, file system, network)
- Отсутствия валидации входных данных
- Избыточных привилегий
- Потенциала для SSRF, LFI, RCE
"""

import re
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import Severity, DANGEROUS_PATTERNS


class ToolAbuseDetector:
    """Детектор уязвимостей к tool abuse атакам."""
    
    # Дополнительные опасные паттерны специфичные для tool abuse
    TOOL_ABUSE_PATTERNS = {
        # Remote Code Execution (RCE)
        "rce_subprocess": {
            "pattern": r"subprocess\.(run|call|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True",
            "severity": Severity.CRITICAL,
            "attack_type": "RCE",
            "description": "Command injection через subprocess с shell=True",
            "recommendation": "Используйте shell=False и передавайте аргументы списком"
        },
        "rce_os_system": {
            "pattern": r"os\.(system|popen|exec\w*)\s*\(",
            "severity": Severity.CRITICAL,
            "attack_type": "RCE",
            "description": "Выполнение системных команд через os module",
            "recommendation": "Избегайте os.system/popen, используйте subprocess с shell=False"
        },
        "rce_eval": {
            "pattern": r"\b(eval|exec|compile)\s*\([^)]*\w+",
            "severity": Severity.CRITICAL,
            "attack_type": "RCE",
            "description": "Выполнение произвольного Python кода",
            "recommendation": "Никогда не используйте eval/exec с пользовательским вводом"
        },
        
        # Local File Inclusion (LFI) / Path Traversal
        "lfi_open": {
            "pattern": r"open\s*\(\s*[^,)]+\s*[,)]",
            "severity": Severity.HIGH,
            "attack_type": "LFI",
            "description": "Чтение файлов без валидации пути (path traversal)",
            "recommendation": "Валидируйте пути, используйте os.path.realpath и whitelist директорий"
        },
        "lfi_path_join": {
            "pattern": r"os\.path\.join\s*\([^)]*\+",
            "severity": Severity.MEDIUM,
            "attack_type": "LFI",
            "description": "Конкатенация путей может привести к path traversal",
            "recommendation": "Проверяйте результат на выход за пределы разрешённой директории"
        },
        
        # Server-Side Request Forgery (SSRF)
        "ssrf_requests": {
            "pattern": r"requests\.(get|post|put|delete|patch|head|options)\s*\([^)]*\w+",
            "severity": Severity.HIGH,
            "attack_type": "SSRF",
            "description": "HTTP запросы с пользовательским URL (SSRF)",
            "recommendation": "Валидируйте URL, используйте whitelist доменов, блокируйте внутренние адреса"
        },
        "ssrf_urllib": {
            "pattern": r"urllib\.(request\.)?urlopen\s*\(",
            "severity": Severity.HIGH,
            "attack_type": "SSRF",
            "description": "HTTP запросы через urllib (SSRF)",
            "recommendation": "Используйте whitelist URL и блокируйте локальные адреса"
        },
        
        # SQL Injection
        "sqli_format": {
            "pattern": r"(execute|cursor\.execute)\s*\([^)]*(%s|%d|\{|\+|f['\"])",
            "severity": Severity.CRITICAL,
            "attack_type": "SQLi",
            "description": "SQL запрос с форматированием строки (SQL injection)",
            "recommendation": "Используйте параметризованные запросы"
        },
        "sqli_fstring": {
            "pattern": r"f['\"].*?(SELECT|INSERT|UPDATE|DELETE|DROP).*?{",
            "severity": Severity.CRITICAL,
            "attack_type": "SQLi",
            "description": "SQL запрос через f-string (SQL injection)",
            "recommendation": "Используйте параметризованные запросы, не f-strings"
        },
        
        # Deserialization
        "deser_pickle": {
            "pattern": r"pickle\.(load|loads)\s*\(",
            "severity": Severity.HIGH,
            "attack_type": "Deserialization",
            "description": "Небезопасная десериализация pickle",
            "recommendation": "Не используйте pickle для ненадёжных данных"
        },
        "deser_yaml": {
            "pattern": r"yaml\.load\s*\([^)]*\)(?!\s*,\s*Loader\s*=)",
            "severity": Severity.HIGH,
            "attack_type": "Deserialization",
            "description": "yaml.load без SafeLoader",
            "recommendation": "Используйте yaml.safe_load или Loader=yaml.SafeLoader"
        },
        
        # Information Disclosure
        "info_env": {
            "pattern": r"os\.(environ|getenv)\s*\[?\s*['\"]?\w*['\"]?\s*\]?",
            "severity": Severity.MEDIUM,
            "attack_type": "Info Disclosure",
            "description": "Доступ к переменным окружения",
            "recommendation": "Ограничьте доступ к конкретным переменным через whitelist"
        },
        "info_secrets": {
            "pattern": r"(password|secret|api_key|token|credential)\s*[=:]\s*['\"]",
            "severity": Severity.HIGH,
            "attack_type": "Info Disclosure",
            "description": "Хардкод секретов в коде",
            "recommendation": "Используйте переменные окружения или secret manager"
        }
    }
    
    # Паттерны валидации (их НАЛИЧИЕ — хорошо)
    VALIDATION_PATTERNS = {
        "type_check": r"isinstance\s*\(",
        "none_check": r"if\s+\w+\s+(is\s+None|==\s*None|!=\s*None)",
        "empty_check": r"if\s+(not\s+)?\w+\s*:",
        "length_check": r"len\s*\(\s*\w+\s*\)",
        "regex_validate": r"re\.(match|search|fullmatch)\s*\(",
        "whitelist_check": r"if\s+\w+\s+(not\s+)?in\s+\[",
        "path_validate": r"os\.path\.(exists|isfile|isdir|realpath|abspath)",
        "url_validate": r"(urlparse|parse_url|validate_url)",
        "sanitize": r"(sanitize|escape|clean|filter)\w*\s*\("
    }
    
    def __init__(self):
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.vuln_counter = 0
    
    def analyze(
        self,
        tools: List[Dict[str, Any]],
        agent_name: str = "unknown"
    ) -> Dict[str, Any]:
        """
        Анализирует инструменты на уязвимости к tool abuse.
        
        Args:
            tools: Список инструментов с source_code.
            agent_name: Имя агента.
            
        Returns:
            Результат анализа с уязвимостями и рекомендациями.
        """
        self.vulnerabilities = []
        self.vuln_counter = 0
        
        result = {
            "status": "success",
            "agent_name": agent_name,
            "vulnerabilities": [],
            "tools_analyzed": [],
            "attack_vectors": {},  # RCE, SSRF, SQLi, etc.
            "tool_abuse_score": 100,
            "recommendations": []
        }
        
        if not tools:
            result["recommendations"].append(
                "Агент не имеет инструментов — риск tool abuse отсутствует."
            )
            return result
        
        for tool in tools:
            tool_result = self._analyze_single_tool(tool)
            result["tools_analyzed"].append(tool_result)
            result["vulnerabilities"].extend(tool_result["vulnerabilities"])
            
            # Обновляем attack vectors
            for vuln in tool_result["vulnerabilities"]:
                attack_type = vuln.get("attack_type", "Unknown")
                if attack_type not in result["attack_vectors"]:
                    result["attack_vectors"][attack_type] = []
                result["attack_vectors"][attack_type].append({
                    "tool": tool.get("name", "unknown"),
                    "vulnerability": vuln["id"]
                })
            
            # Уменьшаем score
            for vuln in tool_result["vulnerabilities"]:
                severity = Severity(vuln["severity"])
                result["tool_abuse_score"] -= self._get_penalty(severity)
        
        # Ограничиваем score
        result["tool_abuse_score"] = max(0, result["tool_abuse_score"])
        
        # Формируем рекомендации
        self._generate_recommendations(result)
        
        return result
    
    def _analyze_single_tool(self, tool: Dict[str, Any]) -> Dict[str, Any]:
        """Анализирует один инструмент."""
        tool_name = tool.get("name", "unknown_tool")
        source_code = tool.get("source_code", "")
        parameters = tool.get("parameters", [])
        line_number = tool.get("line_number", 0)
        
        tool_result = {
            "name": tool_name,
            "line_number": line_number,
            "vulnerabilities": [],
            "has_validation": False,
            "validation_types": [],
            "risk_level": "low"
        }
        
        if not source_code:
            return tool_result
        
        # Проверка 1: Опасные паттерны
        for pattern_name, pattern_info in self.TOOL_ABUSE_PATTERNS.items():
            if re.search(pattern_info["pattern"], source_code, re.IGNORECASE | re.MULTILINE):
                vuln = self._create_vulnerability(
                    pattern_info["description"],
                    pattern_info["severity"],
                    f"{tool_name}()",
                    pattern_info["recommendation"],
                    pattern_info["attack_type"]
                )
                tool_result["vulnerabilities"].append(vuln)
                tool_result["risk_level"] = self._update_risk_level(
                    tool_result["risk_level"],
                    pattern_info["severity"]
                )
        
        # Проверка 2: Наличие валидации
        for validation_name, validation_pattern in self.VALIDATION_PATTERNS.items():
            if re.search(validation_pattern, source_code):
                tool_result["has_validation"] = True
                tool_result["validation_types"].append(validation_name)
        
        # Проверка 3: Параметры без валидации
        if parameters and not tool_result["has_validation"]:
            vuln = self._create_vulnerability(
                f"Инструмент {tool_name} принимает параметры без валидации",
                Severity.MEDIUM,
                f"{tool_name}()",
                "Добавьте валидацию типов и значений для всех параметров",
                "Input Validation"
            )
            tool_result["vulnerabilities"].append(vuln)
        
        return tool_result
    
    def _create_vulnerability(
        self,
        description: str,
        severity: Severity,
        location: str,
        recommendation: str,
        attack_type: str = "Unknown"
    ) -> Dict[str, Any]:
        """Создаёт запись об уязвимости."""
        self.vuln_counter += 1
        return {
            "id": f"ABUSE-{self.vuln_counter:03d}",
            "category": "tool_abuse",
            "severity": severity.value,
            "attack_type": attack_type,
            "title": f"[{attack_type}] {description[:40]}...",
            "description": description,
            "location": location,
            "recommendation": recommendation
        }
    
    def _get_penalty(self, severity: Severity) -> int:
        """Возвращает штраф за уязвимость."""
        penalties = {
            Severity.CRITICAL: 30,
            Severity.HIGH: 20,
            Severity.MEDIUM: 10,
            Severity.LOW: 5,
            Severity.INFO: 0
        }
        return penalties.get(severity, 0)
    
    def _update_risk_level(self, current: str, severity: Severity) -> str:
        """Обновляет уровень риска."""
        risk_order = ["low", "medium", "high", "critical"]
        severity_to_risk = {
            Severity.CRITICAL: "critical",
            Severity.HIGH: "high",
            Severity.MEDIUM: "medium",
            Severity.LOW: "low",
            Severity.INFO: "low"
        }
        
        new_risk = severity_to_risk.get(severity, "low")
        if risk_order.index(new_risk) > risk_order.index(current):
            return new_risk
        return current
    
    def _generate_recommendations(self, result: Dict[str, Any]) -> None:
        """Генерирует рекомендации на основе найденных проблем."""
        attack_vectors = result.get("attack_vectors", {})
        
        # Рекомендации по типам атак
        if "RCE" in attack_vectors:
            result["recommendations"].insert(0,
                "КРИТИЧНО: Обнаружены RCE уязвимости! Удалите или изолируйте опасные функции."
            )
            result["recommendations"].append(
                "Используйте before_tool_callback для валидации команд перед выполнением."
            )
        
        if "SSRF" in attack_vectors:
            result["recommendations"].append(
                "Для защиты от SSRF: валидируйте URL, используйте whitelist доменов, "
                "блокируйте локальные адреса (127.0.0.1, localhost, 10.x.x.x, 192.168.x.x)."
            )
        
        if "SQLi" in attack_vectors:
            result["recommendations"].append(
                "Для защиты от SQL injection: используйте ТОЛЬКО параметризованные запросы. "
                "Никогда не форматируйте SQL строки вручную."
            )
        
        if "LFI" in attack_vectors:
            result["recommendations"].append(
                "Для защиты от path traversal: используйте os.path.realpath и проверяйте, "
                "что путь находится в разрешённой директории."
            )
        
        # Общие рекомендации
        tools_without_validation = [
            t["name"] for t in result.get("tools_analyzed", [])
            if not t.get("has_validation")
        ]
        
        if tools_without_validation:
            result["recommendations"].append(
                f"Добавьте валидацию входных данных для: {', '.join(tools_without_validation)}"
            )


def detect_tool_abuse_vulnerabilities(
    tools: List[Dict[str, Any]],
    agent_name: str = "unknown"
) -> Dict[str, Any]:
    """
    Функция-обёртка для детекции tool abuse уязвимостей.
    
    Args:
        tools: Список инструментов.
        agent_name: Имя агента.
        
    Returns:
        Результат анализа.
    """
    detector = ToolAbuseDetector()
    return detector.analyze(tools, agent_name)

