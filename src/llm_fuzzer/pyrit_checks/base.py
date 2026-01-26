"""
Base class for PyRIT security checks.

Использует РЕАЛЬНЫЕ PyRIT компоненты:
- pyrit.prompt_target.OpenAIChatTarget для отправки промптов
- pyrit.executor.attack.PromptSendingAttack для оркестрации атак
- pyrit.score.* для оценки ответов
- pyrit.memory.CentralMemory для хранения

Документация: https://azure.github.io/PyRIT/code/user_guide.html
"""

import logging
import httpx
import warnings
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Type
import time

from llm_fuzzer.core.target import TargetConfig
from llm_fuzzer.core.check import (
    CheckConfig,
    CheckResult,
    CheckStatus,
    CheckCategory,
    Severity,
    Finding,
)


# Подавляем SSL предупреждения
warnings.filterwarnings("ignore", message="Unverified HTTPS request")


# Реестр проверок
_REGISTERED_CHECKS: Dict[str, Type["BasePyRITCheck"]] = {}


def register_check(check_id: str):
    """
    Декоратор для регистрации PyRIT проверки.
    
    Использование:
        @register_check("my-check-id")
        class MyCheck(BasePyRITCheck):
            ...
    """
    def decorator(cls: Type["BasePyRITCheck"]):
        _REGISTERED_CHECKS[check_id] = cls
        cls.check_id = check_id
        return cls
    return decorator


def get_registered_checks() -> Dict[str, Type["BasePyRITCheck"]]:
    """Получить все зарегистрированные проверки."""
    return _REGISTERED_CHECKS.copy()


@dataclass
class PyRITCheckResult:
    """Результат одной атаки."""
    prompt: str
    response: str
    is_vulnerable: bool
    confidence: float
    evidence: str
    metadata: Dict[str, Any] = field(default_factory=dict)


def initialize_pyrit_memory():
    """
    Инициализировать PyRIT Memory.
    
    PyRIT требует настроенную memory для работы.
    Используем SQLiteMemory как стандартный вариант.
    """
    try:
        from pyrit.memory import CentralMemory
        
        # Проверяем, есть ли уже инициализированная memory
        try:
            CentralMemory.get_memory_instance()
            return True
        except:
            pass
        
        # Инициализируем SQLiteMemory
        try:
            from pyrit.memory import SQLiteMemory
            memory = SQLiteMemory()
            CentralMemory.set_memory_instance(memory)
            return True
        except ImportError:
            # Fallback на DuckDB если SQLite недоступен
            from pyrit.memory import DuckDBMemory
            memory = DuckDBMemory()
            CentralMemory.set_memory_instance(memory)
            return True
            
    except Exception as e:
        logging.warning(f"Failed to initialize PyRIT memory: {e}")
        return False


class BasePyRITCheck(ABC):
    """
    Базовый класс для PyRIT проверок.
    
    Использует реальные PyRIT компоненты:
    - OpenAIChatTarget для отправки промптов
    - PromptSendingAttack для оркестрации
    - Scorers для оценки ответов
    
    Каждая проверка должна реализовать run() метод.
    """
    
    # Метаданные проверки (переопределить в наследниках)
    check_id: str = "base"
    name: str = "Base Check"
    description: str = "Base PyRIT check"
    category: CheckCategory = CheckCategory.CUSTOM
    severity: Severity = Severity.MEDIUM
    
    def __init__(self):
        self._logger = logging.getLogger(self.__class__.__name__)
        self._pyrit_target = None
        self._memory_initialized = False
    
    def _ensure_memory(self):
        """Убедиться что PyRIT memory инициализирована."""
        if not self._memory_initialized:
            self._memory_initialized = initialize_pyrit_memory()
    
    @abstractmethod
    async def run(
        self,
        target: TargetConfig,
        config: Optional[CheckConfig] = None,
    ) -> List[PyRITCheckResult]:
        """
        Выполнить проверку.
        
        Args:
            target: Конфигурация целевого LLM
            config: Опциональная конфигурация проверки
            
        Returns:
            Список результатов атак
        """
        pass
    
    async def execute(
        self,
        target: TargetConfig,
        config: Optional[CheckConfig] = None,
    ) -> CheckResult:
        """
        Выполнить проверку и вернуть CheckResult.
        
        Обёртка над run() для интеграции с LLM Fuzzer.
        """
        start_time = time.time()
        
        try:
            # Инициализируем PyRIT memory
            self._ensure_memory()
            
            results = await self.run(target, config)
            
            # Конвертируем в findings и считаем статистику
            findings = []
            total_prompts = len(results)
            successful_attacks = 0
            
            for r in results:
                if r.is_vulnerable:
                    successful_attacks += 1
                    findings.append(Finding(
                        prompt=r.prompt,
                        response=r.response,
                        evidence=r.evidence,
                        confidence=r.confidence,
                        metadata=r.metadata,
                    ))
            
            duration = time.time() - start_time
            
            return CheckResult(
                check_id=self.check_id,
                check_name=self.name,
                status=CheckStatus.FAILED if findings else CheckStatus.PASSED,
                category=self.category,
                severity=self.severity,
                engine_used="pyrit",
                duration_seconds=duration,
                findings=findings,
                total_prompts=total_prompts,
                successful_attacks=successful_attacks,
            )
            
        except Exception as e:
            duration = time.time() - start_time
            self._logger.error(f"Check failed: {e}")
            
            return CheckResult(
                check_id=self.check_id,
                check_name=self.name,
                status=CheckStatus.ERROR,
                category=self.category,
                severity=self.severity,
                engine_used="pyrit",
                duration_seconds=duration,
                findings=[],
                error_message=str(e),
                total_prompts=0,
                successful_attacks=0,
            )
    
    def _create_openai_target(self, target: TargetConfig):
        """
        Создать PyRIT OpenAIChatTarget.
        
        Использует реальный PyRIT target с отключённой SSL верификацией.
        
        Документация: https://azure.github.io/PyRIT/code/user_guide.html#openai-chat-target
        """
        from pyrit.prompt_target import OpenAIChatTarget
        
        # Формируем endpoint (PyRIT ожидает base URL)
        endpoint = target.endpoint
        if endpoint.endswith("/chat/completions"):
            endpoint = endpoint.rsplit("/chat/completions", 1)[0]
        
        # Создаём httpx клиент с отключённой SSL верификацией
        # PyRIT OpenAIChatTarget использует AsyncOpenAI внутри,
        # который принимает http_client через конструктор
        http_client = httpx.AsyncClient(
            verify=False,
            timeout=httpx.Timeout(target.timeout or 60.0),
        )
        
        # PyRIT принимает httpx_client_kwargs для передачи в AsyncOpenAI
        # Или напрямую http_client в некоторых версиях
        try:
            # Попытка 1: Передать через httpx_client_kwargs (PyRIT 0.10+)
            pyrit_target = OpenAIChatTarget(
                model_name=target.model or "gpt-4",
                endpoint=endpoint,
                api_key=target.get_api_key(),
                httpx_client_kwargs={"http_client": http_client},
            )
        except TypeError:
            # Попытка 2: Передать напрямую (некоторые версии PyRIT)
            try:
                pyrit_target = OpenAIChatTarget(
                    model_name=target.model or "gpt-4",
                    endpoint=endpoint,
                    api_key=target.get_api_key(),
                    http_client=http_client,
                )
            except TypeError:
                # Попытка 3: Без SSL bypass (последний fallback)
                self._logger.warning("Could not configure SSL bypass for OpenAIChatTarget")
                pyrit_target = OpenAIChatTarget(
                    model_name=target.model or "gpt-4",
                    endpoint=endpoint,
                    api_key=target.get_api_key(),
                )
        
        self._logger.debug(f"Created OpenAIChatTarget: {endpoint}, model={target.model}")
        return pyrit_target
    
    def _create_http_target(
        self, 
        target: TargetConfig,
        body_template: Optional[Dict[str, Any]] = None,
        response_json_path: str = "$.choices[0].message.content",
    ):
        """
        Создать PyRIT HTTPTarget для кастомных API.
        
        Используется когда нужен полный контроль над request/response.
        Например, для tools API.
        
        Документация: https://azure.github.io/PyRIT/code/user_guide.html#http-target
        """
        from pyrit.prompt_target import HTTPTarget
        
        endpoint = target.endpoint
        if not endpoint.endswith("/chat/completions"):
            if endpoint.endswith("/v1"):
                endpoint = endpoint + "/chat/completions"
            else:
                endpoint = endpoint.rstrip("/") + "/v1/chat/completions"
        
        # Дефолтный body template
        if body_template is None:
            body_template = {
                "model": target.model or "gpt-4",
                "messages": [{"role": "user", "content": "{prompt}"}],
            }
        
        # Создаём HTTPTarget
        http_target = HTTPTarget(
            http_request={
                "method": "POST",
                "url": endpoint,
                "headers": {
                    "Authorization": f"Bearer {target.get_api_key()}",
                    "Content-Type": "application/json",
                },
                "body": body_template,
            },
            response_json_path=response_json_path,
            use_tls=not target.disable_ssl_verify,
        )
        
        self._logger.debug(f"Created HTTPTarget: {endpoint}")
        return http_target
    
    async def run_prompt_sending_attack(
        self,
        target: TargetConfig,
        prompts: List[str],
        max_prompts: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Выполнить атаку через PyRIT PromptSendingAttack.
        
        Это основной способ отправки промптов через PyRIT!
        
        Args:
            target: Конфигурация целевого LLM
            prompts: Список атакующих промптов
            max_prompts: Ограничение количества промптов
            
        Returns:
            Список результатов от PyRIT (prompt, response pairs)
        """
        from pyrit.orchestrator import PromptSendingOrchestrator
        
        # Ограничиваем промпты
        if max_prompts:
            prompts = prompts[:max_prompts]
        
        # Создаём PyRIT target
        pyrit_target = self._create_openai_target(target)
        
        results = []
        
        try:
            # Создаём PyRIT Orchestrator
            # PromptSendingOrchestrator - основной способ отправки промптов
            async with PromptSendingOrchestrator(
                objective_target=pyrit_target,
            ) as orchestrator:
                
                # Отправляем промпты через PyRIT
                responses = await orchestrator.send_prompts_async(
                    prompt_list=prompts
                )
                
                # Парсим результаты
                for response in responses:
                    prompt_text = ""
                    response_text = ""
                    
                    # Извлекаем текст из PyRIT response
                    if hasattr(response, 'request_pieces'):
                        for piece in response.request_pieces:
                            if hasattr(piece, 'original_value'):
                                prompt_text = piece.original_value
                                break
                    
                    if hasattr(response, 'response_pieces'):
                        for piece in response.response_pieces:
                            if hasattr(piece, 'original_value'):
                                response_text = piece.original_value
                                break
                    
                    results.append({
                        "prompt": prompt_text,
                        "response": response_text,
                        "pyrit_response": response,
                    })
        
        except Exception as e:
            self._logger.error(f"PromptSendingAttack failed: {e}")
            # Fallback: отправляем промпты напрямую через target
            for prompt in prompts:
                try:
                    response_text = await self._send_prompt_direct(pyrit_target, prompt)
                    results.append({
                        "prompt": prompt,
                        "response": response_text or "",
                        "pyrit_response": None,
                    })
                except Exception as inner_e:
                    self._logger.warning(f"Direct send failed: {inner_e}")
        
        return results
    
    async def _send_prompt_direct(self, pyrit_target, prompt: str) -> Optional[str]:
        """
        Отправить промпт напрямую через PyRIT target.
        
        Fallback метод если PromptSendingOrchestrator недоступен.
        """
        try:
            from pyrit.models import PromptRequestPiece, PromptRequestResponse
            
            # Создаём request
            request = PromptRequestPiece(
                role="user",
                original_value=prompt,
            )
            
            # Отправляем через target
            response = await pyrit_target.send_prompt_async(
                prompt_request=PromptRequestResponse(request_pieces=[request])
            )
            
            # Извлекаем текст
            if response and hasattr(response, 'request_pieces'):
                for piece in response.request_pieces:
                    if hasattr(piece, 'original_value'):
                        return piece.original_value
            
            return str(response) if response else None
            
        except Exception as e:
            self._logger.warning(f"Direct prompt send failed: {e}")
            return None
    
    async def score_responses(
        self,
        responses: List[Dict[str, Any]],
        scorer_type: str = "substring",
        patterns: Optional[List[str]] = None,
        true_description: Optional[str] = None,
        false_description: Optional[str] = None,
        scorer_target: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        """
        Оценить ответы через PyRIT Scorer.
        
        Args:
            responses: Результаты от run_prompt_sending_attack
            scorer_type: Тип scorer ("substring", "true_false", "refusal")
            patterns: Паттерны для SubStringScorer
            true_description: Описание для True в TrueFalseScorer
            false_description: Описание для False в TrueFalseScorer
            scorer_target: Target для LLM-based scorers
            
        Returns:
            Responses с добавленными scores
        """
        from pyrit.score import SubStringScorer
        
        scored_results = []
        
        for resp in responses:
            response_text = resp.get("response", "")
            is_vulnerable = False
            evidence = ""
            confidence = 0.0
            
            if scorer_type == "substring" and patterns:
                # SubStringScorer - ищем паттерны в ответе
                for pattern in patterns:
                    try:
                        scorer = SubStringScorer(substring=pattern.lower())
                        
                        # PyRIT scorer API
                        from pyrit.models import PromptRequestPiece
                        piece = PromptRequestPiece(
                            role="assistant",
                            original_value=response_text,
                        )
                        
                        scores = await scorer.score_async(
                            request_response=piece
                        )
                        
                        if scores:
                            score = scores[0]
                            if hasattr(score, 'get_value') and score.get_value():
                                is_vulnerable = True
                                evidence = f"PyRIT SubStringScorer: pattern '{pattern}' found"
                                confidence = 0.9
                                break
                                
                    except Exception as e:
                        self._logger.debug(f"Scorer error for '{pattern}': {e}")
            
            elif scorer_type == "true_false" and scorer_target:
                # SelfAskTrueFalseScorer - LLM-based scoring
                try:
                    from pyrit.score import SelfAskTrueFalseScorer
                    
                    scorer = SelfAskTrueFalseScorer(
                        chat_target=scorer_target,
                        true_description=true_description or "Vulnerable",
                        false_description=false_description or "Safe",
                    )
                    
                    from pyrit.models import PromptRequestPiece
                    piece = PromptRequestPiece(
                        role="assistant",
                        original_value=response_text,
                    )
                    
                    scores = await scorer.score_async(request_response=piece)
                    
                    if scores:
                        score = scores[0]
                        if hasattr(score, 'get_value') and score.get_value():
                            is_vulnerable = True
                            evidence = f"PyRIT SelfAskTrueFalseScorer: {true_description}"
                            confidence = 0.85
                            
                except Exception as e:
                    self._logger.debug(f"TrueFalse scorer error: {e}")
            
            scored_results.append({
                **resp,
                "is_vulnerable": is_vulnerable,
                "evidence": evidence,
                "confidence": confidence,
            })
        
        return scored_results
