"""
InsecureOpenAIChatTarget - OpenAIChatTarget с отключенной проверкой SSL.

Используется для тестирования endpoint-ов с self-signed сертификатами
или в локальных средах разработки.

ВНИМАНИЕ: Не используйте в production среде!
"""

import logging
import warnings
from typing import Any, Callable, Optional, Awaitable

import httpx
from openai import AsyncOpenAI

from pyrit.prompt_target import OpenAIChatTarget

logger = logging.getLogger(__name__)


class InsecureOpenAIChatTarget(OpenAIChatTarget):
    """
    OpenAIChatTarget с отключенной проверкой SSL сертификатов.
    
    Эта версия target-а отключает SSL верификацию, что позволяет
    подключаться к endpoint-ам с self-signed сертификатами.
    
    ВНИМАНИЕ: Использование этого класса создаёт уязвимость для
    MITM-атак. Используйте только в тестовых средах!
    
    Пример использования:
    
    ```python
    target = InsecureOpenAIChatTarget(
        endpoint="https://your-local-endpoint:8443/v1",
        api_key="your-api-key",
        model_name="your-model",
    )
    ```
    
    Args:
        Все аргументы наследуются от OpenAIChatTarget
    """

    def __init__(
        self,
        *,
        suppress_ssl_warning: bool = True,
        **kwargs: Any,
    ) -> None:
        """
        Инициализация InsecureOpenAIChatTarget.

        Args:
            suppress_ssl_warning: Подавлять предупреждения о небезопасном SSL.
                По умолчанию True.
            **kwargs: Аргументы для OpenAIChatTarget
        """
        self._suppress_ssl_warning = suppress_ssl_warning
        super().__init__(**kwargs)

    def _initialize_openai_client(self) -> None:
        """
        Инициализация OpenAI клиента с отключенной SSL верификацией.
        
        Переопределяет стандартную инициализацию для использования
        httpx клиента с verify=False.
        """
        # Предупреждение о небезопасном соединении
        if not self._suppress_ssl_warning:
            logger.warning(
                "⚠️  SSL certificate verification is DISABLED for this target. "
                "This makes the connection vulnerable to MITM attacks. "
                "Only use in development/testing environments!"
            )
        
        # Подавляем предупреждения urllib3 о небезопасных запросах
        if self._suppress_ssl_warning:
            warnings.filterwarnings("ignore", message="Unverified HTTPS request")
        
        # Собираем дополнительные headers
        default_headers = {}
        if hasattr(self, '_headers') and self._headers:
            default_headers.update(self._headers)
        
        # Создаём httpx клиент с отключенной SSL верификацией
        http_client = httpx.AsyncClient(
            verify=False,
            headers=default_headers,
            timeout=httpx.Timeout(60.0, connect=10.0),  # Разумные таймауты
        )
        
        # Инициализируем AsyncOpenAI с кастомным http клиентом
        self._async_client = AsyncOpenAI(
            base_url=self._endpoint,
            api_key=self._api_key,
            http_client=http_client,
        )
        
        logger.info(
            f"Initialized InsecureOpenAIChatTarget with SSL verification disabled. "
            f"Endpoint: {self._endpoint}"
        )


def get_target(
    endpoint: str,
    api_key: str,
    model_name: str,
    disable_ssl_verify: bool = False,
    **kwargs: Any,
) -> OpenAIChatTarget:
    """
    Фабричная функция для создания target-а с опциональным отключением SSL.
    
    Args:
        endpoint: URL endpoint-а
        api_key: API ключ
        model_name: Название модели
        disable_ssl_verify: Отключить проверку SSL. По умолчанию False.
        **kwargs: Дополнительные аргументы для target-а
        
    Returns:
        OpenAIChatTarget или InsecureOpenAIChatTarget в зависимости от настроек
    """
    if disable_ssl_verify:
        return InsecureOpenAIChatTarget(
            endpoint=endpoint,
            api_key=api_key,
            model_name=model_name,
            **kwargs,
        )
    else:
        return OpenAIChatTarget(
            endpoint=endpoint,
            api_key=api_key,
            model_name=model_name,
            **kwargs,
        )
