"""
RealPyRITAdapter - интерфейс к проверкам на базе PyRIT.

PyRIT — это ФРЕЙМВОРК, а не готовый инструмент.
Проверки написаны в модуле pyrit_checks/ и используют PyRIT API.
"""

import asyncio
import logging
import time
import warnings
from typing import List, Optional, Dict, Any

from .base import BaseAdapter
from llm_fuzzer.core.target import TargetConfig
from llm_fuzzer.core.check import (
    CheckConfig, 
    CheckResult, 
    CheckStatus,
    CheckCategory,
    EngineType,
    Finding,
)

logger = logging.getLogger(__name__)


def suppress_ssl_warnings():
    """Подавить SSL warnings."""
    warnings.filterwarnings("ignore", message="Unverified HTTPS request")
    warnings.filterwarnings("ignore", message=".*certificate.*")
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except (ImportError, AttributeError):
        pass


class RealPyRITAdapter(BaseAdapter):
    """
    Адаптер для PyRIT проверок.
    
    Использует проверки из модуля pyrit_checks/:
    - SystemPromptLeakageCheck
    - ToolCallsAbuseCheck
    - И любые пользовательские проверки
    """
    
    def __init__(self):
        super().__init__()
        self._pyrit_available = False
        self._pyrit_version: Optional[str] = None
        self._memory = None
        self._checks: Dict[str, Any] = {}
    
    @property
    def name(self) -> str:
        return "pyrit"
    
    @property
    def version(self) -> str:
        return self._pyrit_version or "unknown"
    
    async def initialize(self) -> None:
        """Инициализация PyRIT и загрузка проверок."""
        try:
            import pyrit
            from pyrit.memory import CentralMemory
            
            self._pyrit_version = getattr(pyrit, "__version__", "available")
            
            # Инициализируем PyRIT memory (SQLiteMemory для v0.10+, DuckDBMemory для старых)
            try:
                try:
                    from pyrit.memory import SQLiteMemory
                    self._memory = SQLiteMemory()
                except ImportError:
                    from pyrit.memory import DuckDBMemory
                    self._memory = DuckDBMemory()
                CentralMemory.set_memory_instance(self._memory)
            except Exception as e:
                self._logger.warning(f"PyRIT memory init failed: {e}")
            
            self._pyrit_available = True
            self._initialized = True
            
            # Загружаем зарегистрированные проверки
            self._load_checks()
            
            self._logger.info(f"PyRIT initialized: v{self._pyrit_version}, checks: {len(self._checks)}")
            
        except ImportError as e:
            self._logger.warning(f"PyRIT not available: {e}")
            self._pyrit_available = False
            self._initialized = False
    
    def _load_checks(self):
        """Загрузить все зарегистрированные PyRIT проверки."""
        try:
            from llm_fuzzer.pyrit_checks import get_registered_checks
            
            self._checks = get_registered_checks()
            
            for check_id, check_class in self._checks.items():
                self._logger.debug(f"Loaded PyRIT check: {check_id} ({check_class.name})")
                
        except ImportError as e:
            self._logger.warning(f"Failed to load PyRIT checks: {e}")
    
    def supports_check(self, check: CheckConfig) -> bool:
        return check.engine in [EngineType.PYRIT, EngineType.AUTO, None]
    
    async def cleanup(self) -> None:
        if self._memory:
            try:
                self._memory.dispose_engine()
            except Exception:
                pass
    
    async def run_check(
        self, 
        target: TargetConfig, 
        check: CheckConfig
    ) -> CheckResult:
        """Запустить проверку через PyRIT."""
        start_time = time.time()
        
        suppress_ssl_warnings()
        
        if not self._pyrit_available:
            return self._create_error_result(
                check, 
                Exception("PyRIT not available"),
                time.time() - start_time
            )
        
        try:
            # Определяем какую проверку использовать
            pyrit_check = self._get_check_for_config(check)
            
            if pyrit_check:
                # Используем зарегистрированную проверку
                result = await pyrit_check.execute(target, check)
                return result
            else:
                # Fallback: используем базовую логику для обратной совместимости
                findings = await self._run_basic_check(target, check)
                
                duration = time.time() - start_time
                
                if findings:
                    return self._create_failed_result(check, findings, duration)
                else:
                    return self._create_passed_result(check, duration)
                
        except Exception as e:
            duration = time.time() - start_time
            self._logger.error(f"PyRIT check failed: {e}")
            return self._create_error_result(check, e, duration)
    
    def _get_check_for_config(self, config: CheckConfig):
        """Получить PyRIT проверку для конфига."""
        # 1. Ищем по check_id
        if config.id in self._checks:
            return self._checks[config.id]()
        
        # 2. Ищем по pyrit_check параметру
        pyrit_check_id = config.params.get("pyrit_check") if config.params else None
        if pyrit_check_id and pyrit_check_id in self._checks:
            return self._checks[pyrit_check_id]()
        
        # 3. Определяем по категории
        category_map = {
            CheckCategory.LEAKAGE: "pyrit-system-prompt-leakage",
            CheckCategory.TOOL_ABUSE: "pyrit-tool-calls-abuse",
        }
        
        default_check_id = category_map.get(config.category)
        if default_check_id and default_check_id in self._checks:
            return self._checks[default_check_id]()
        
        return None
    
    async def _run_basic_check(
        self,
        target: TargetConfig,
        check: CheckConfig
    ) -> List[Finding]:
        """
        Базовая проверка для обратной совместимости.
        
        Используется когда нет специализированной проверки.
        """
        from llm_fuzzer.pyrit_checks.base import BasePyRITCheck
        
        findings = []
        
        # Получаем промпты из конфига
        prompts = check.params.get("prompts", []) if check.params else []
        if not prompts:
            return findings
        
        # Создаём базовый PyRIT target
        pyrit_target = self._create_pyrit_target(target)
        
        # Получаем keywords для детекции
        detect_keywords = check.params.get("detect_keywords", []) if check.params else []
        
        for prompt in prompts[:10]:
            try:
                response = await self._send_prompt(pyrit_target, prompt)
                
                if not response:
                    continue
                
                # Простая keyword-based детекция
                is_vulnerable = False
                evidence = ""
                
                response_lower = response.lower()
                for keyword in detect_keywords:
                    if keyword.lower() in response_lower:
                        is_vulnerable = True
                        evidence = f"Keyword detected: {keyword}"
                        break
                
                if is_vulnerable:
                    findings.append(Finding(
                        prompt=prompt,
                        response=response,
                        evidence=evidence,
                        confidence=0.8,
                        metadata={
                            "check_type": "basic",
                            "category": str(check.category),
                        }
                    ))
                    
            except Exception as e:
                self._logger.warning(f"Prompt failed: {e}")
        
        return findings
    
    def _create_pyrit_target(self, target: TargetConfig):
        """Создать PyRIT OpenAIChatTarget."""
        import httpx
        from pyrit.prompt_target import OpenAIChatTarget
        
        # Формируем endpoint (PyRIT ожидает base URL без /chat/completions)
        endpoint = target.endpoint
        if endpoint.endswith("/chat/completions"):
            endpoint = endpoint.rsplit("/chat/completions", 1)[0]
        if not endpoint.endswith("/v1"):
            if not endpoint.endswith("/"):
                endpoint = endpoint + "/v1"
        
        # Создаём httpx клиент с отключённой SSL верификацией
        http_client = httpx.AsyncClient(
            verify=False,
            timeout=httpx.Timeout(target.timeout or 60.0),
        )
        
        return OpenAIChatTarget(
            model_name=target.model or "gpt-4",
            endpoint=endpoint,
            api_key=target.get_api_key(),
            httpx_client_kwargs={
                "http_client": http_client,
            },
        )
    
    async def _send_prompt(self, pyrit_target, prompt: str) -> str:
        """Отправить промпт через PyRIT target."""
        from pyrit.models import Message, MessagePiece
        
        try:
            # PyRIT 0.10+ API
            piece = MessagePiece(
                role="user",
                original_value=prompt,
            )
            message = Message([piece])
            
            responses = await pyrit_target.send_prompt_async(message=message)
            
            if responses:
                for resp in responses:
                    if hasattr(resp, 'message_pieces'):
                        for p in resp.message_pieces:
                            if hasattr(p, 'converted_value') and p.converted_value:
                                return p.converted_value
                            if hasattr(p, 'original_value') and p.original_value:
                                return p.original_value
                    return str(resp)
            
            return ""
            
        except Exception as e:
            self._logger.warning(f"PyRIT send failed: {e}")
            return ""
    
    def _create_passed_result(
        self, 
        check: CheckConfig, 
        duration: float,
        total_prompts: int = 0
    ) -> CheckResult:
        return CheckResult(
            check_id=check.id,
            check_name=check.name,
            status=CheckStatus.PASSED,
            category=check.category,
            severity=check.severity,
            engine_used=self.name,
            duration_seconds=duration,
            findings=[],
            total_prompts=total_prompts,
            successful_attacks=0,
        )
    
    def _create_failed_result(
        self, 
        check: CheckConfig, 
        findings: List[Finding],
        duration: float,
        total_prompts: int = 0,
        successful_attacks: int = 0
    ) -> CheckResult:
        return CheckResult(
            check_id=check.id,
            check_name=check.name,
            status=CheckStatus.FAILED,
            category=check.category,
            severity=check.severity,
            engine_used=self.name,
            duration_seconds=duration,
            findings=findings,
            total_prompts=total_prompts,
            successful_attacks=successful_attacks if successful_attacks else len(findings),
        )
    
    def _create_error_result(
        self,
        check: CheckConfig,
        error: Exception,
        duration: float
    ) -> CheckResult:
        return CheckResult(
            check_id=check.id,
            check_name=check.name,
            status=CheckStatus.ERROR,
            category=check.category,
            severity=check.severity,
            engine_used=self.name,
            duration_seconds=duration,
            findings=[],
            error_message=str(error),
            total_prompts=0,
            successful_attacks=0,
        )


def get_available_pyrit_checks() -> List[Dict[str, Any]]:
    """Получить список доступных PyRIT проверок."""
    checks = []
    
    try:
        from llm_fuzzer.pyrit_checks import get_registered_checks
        
        for check_id, check_class in get_registered_checks().items():
            checks.append({
                "id": check_id,
                "name": check_class.name,
                "description": check_class.description,
                "category": str(check_class.category),
                "severity": str(check_class.severity),
                "source": "pyrit_check",
            })
            
    except ImportError:
        pass
    
    return checks
