"""
InsecureRESTGenerator - REST generator без проверки SSL сертификатов.

Этот generator предназначен для тестирования endpoint-ов с self-signed
сертификатами или в закрытых сетях. Все SSL warnings подавлены.
"""

import os
import ssl
import warnings
from typing import List, Union

import httpx

# Подавляем все SSL-related warnings глобально при импорте модуля
warnings.filterwarnings("ignore", message="Unverified HTTPS request")
warnings.filterwarnings("ignore", category=DeprecationWarning, module="ssl")

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    pass

# Импортируем garak Generator
try:
    from garak.generators.base import Generator
except ImportError:
    # Fallback для разработки без garak
    class Generator:
        def __init__(self, name="", generations=1):
            self.name = name
            self.generations = generations


class InsecureRESTGenerator(Generator):
    """
    REST Generator без проверки SSL сертификатов и без warnings.
    
    Особенности:
    - Полностью отключена SSL верификация
    - Подавлены все SSL-related warnings
    - Поддержка кастомных headers
    - Совместимость с OpenAI API format
    
    Использование:
        generator = InsecureRESTGenerator(
            endpoint="https://internal-api.company.com/v1/chat/completions",
            api_key="your-api-key",
            model="gpt-4",
        )
    """
    
    name = "insecure_rest"
    description = "REST generator without SSL verification (no warnings)"
    
    DEFAULT_PARAMS = {
        "temperature": 0.7,
        "max_tokens": 1024,
    }
    
    def __init__(
        self,
        name: str = "",
        generations: int = 1,
        endpoint: str = None,
        api_key: str = None,
        model: str = "gpt-3.5-turbo",
        extra_headers: dict = None,
        timeout: float = 60.0,
        system_prompt: str = None,
    ):
        """
        Инициализация InsecureRESTGenerator.
        
        Args:
            name: Имя generator (для логирования)
            generations: Количество генераций на запрос
            endpoint: URL API endpoint (по умолчанию из OPENAI_API_BASE)
            api_key: API ключ (по умолчанию из OPENAI_API_KEY)
            model: Название модели
            extra_headers: Дополнительные HTTP headers
            timeout: Таймаут запросов в секундах
            system_prompt: Опциональный system prompt
        """
        # Garak Generator.__init__ имеет сигнатуру (name='', config_root=...)
        # generations НЕ передаётся в super().__init__
        super().__init__(name or self.name)
        self.generations = generations  # Устанавливаем атрибут вручную
        
        # Подавляем warnings ещё раз на уровне экземпляра
        self._suppress_ssl_warnings()
        
        # Формируем правильный endpoint
        raw_endpoint = endpoint or os.getenv(
            "OPENAI_API_BASE", 
            "https://api.openai.com/v1/chat/completions"
        )
        # Убеждаемся что путь заканчивается на /chat/completions
        if not raw_endpoint.endswith("/chat/completions"):
            self.endpoint = raw_endpoint.rstrip("/") + "/chat/completions"
        else:
            self.endpoint = raw_endpoint
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self.model = model
        self.extra_headers = extra_headers or {}
        self.timeout = timeout
        self.system_prompt = system_prompt
        
        # Создаём HTTP клиент БЕЗ SSL верификации
        self._client = httpx.Client(
            verify=False,  # Отключаем SSL верификацию
            timeout=timeout,
            http2=True,  # Поддержка HTTP/2 если сервер поддерживает
        )
    
    @staticmethod
    def _suppress_ssl_warnings():
        """Подавить все SSL-related warnings."""
        import warnings
        
        # Подавляем warnings от разных источников
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")
        warnings.filterwarnings("ignore", message=".*certificate.*", category=UserWarning)
        warnings.filterwarnings("ignore", category=DeprecationWarning, module="ssl")
        
        # urllib3 warnings
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except (ImportError, AttributeError):
            pass
        
        # requests warnings (если используется)
        try:
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            warnings.filterwarnings("ignore", category=InsecureRequestWarning)
        except ImportError:
            pass
    
    def generate(
        self, 
        prompt: Union[str, List[str]],
        generations_this_call: int = None,
    ) -> List[str]:
        """
        Сгенерировать ответы для prompt(s).
        
        Args:
            prompt: Один prompt или список промптов
            generations_this_call: Количество генераций (переопределяет self.generations)
            
        Returns:
            Список сгенерированных ответов
        """
        if isinstance(prompt, str):
            prompts = [prompt]
        else:
            prompts = list(prompt)
        
        n = generations_this_call or self.generations
        outputs = []
        
        for p in prompts:
            for _ in range(n):
                try:
                    response = self._call_api(p)
                    outputs.append(response)
                except Exception as e:
                    # Возвращаем ошибку как строку, не ломаем весь процесс
                    outputs.append(f"[ERROR] {type(e).__name__}: {e}")
        
        return outputs
    
    def _call_api(self, prompt: str) -> str:
        """
        Вызвать API и получить ответ.
        
        Args:
            prompt: Текст промпта
            
        Returns:
            Ответ модели
        """
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            **self.extra_headers,
        }
        
        # Формируем messages
        messages = []
        if self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "model": self.model,
            "messages": messages,
            **self.DEFAULT_PARAMS,
        }
        
        response = self._client.post(
            self.endpoint,
            headers=headers,
            json=payload,
        )
        response.raise_for_status()
        
        data = response.json()
        
        # Извлекаем контент из ответа
        if "choices" in data and len(data["choices"]) > 0:
            choice = data["choices"][0]
            if "message" in choice:
                return choice["message"].get("content", "")
            elif "text" in choice:
                return choice["text"]
        
        return str(data)
    
    def __del__(self):
        """Закрыть HTTP клиент при уничтожении объекта."""
        if hasattr(self, "_client") and self._client:
            try:
                self._client.close()
            except Exception:
                pass


class InsecureRESTGeneratorAsync(InsecureRESTGenerator):
    """
    Асинхронная версия InsecureRESTGenerator.
    
    Использует httpx.AsyncClient для асинхронных запросов.
    """
    
    name = "insecure_rest_async"
    description = "Async REST generator without SSL verification"
    
    def __init__(self, *args, **kwargs):
        # Инициализируем базовый класс без создания sync клиента
        super().__init__(*args, **kwargs)
        
        # Закрываем sync клиент, создаём async
        if hasattr(self, "_client") and self._client:
            self._client.close()
        
        self._async_client = httpx.AsyncClient(
            verify=False,
            timeout=self.timeout,
            http2=True,
        )
    
    async def generate_async(
        self, 
        prompt: Union[str, List[str]],
        generations_this_call: int = None,
    ) -> List[str]:
        """
        Асинхронно сгенерировать ответы.
        
        Args:
            prompt: Один prompt или список
            generations_this_call: Количество генераций
            
        Returns:
            Список ответов
        """
        if isinstance(prompt, str):
            prompts = [prompt]
        else:
            prompts = list(prompt)
        
        n = generations_this_call or self.generations
        outputs = []
        
        for p in prompts:
            for _ in range(n):
                try:
                    response = await self._call_api_async(p)
                    outputs.append(response)
                except Exception as e:
                    outputs.append(f"[ERROR] {type(e).__name__}: {e}")
        
        return outputs
    
    async def _call_api_async(self, prompt: str) -> str:
        """Асинхронный вызов API."""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            **self.extra_headers,
        }
        
        messages = []
        if self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "model": self.model,
            "messages": messages,
            **self.DEFAULT_PARAMS,
        }
        
        response = await self._async_client.post(
            self.endpoint,
            headers=headers,
            json=payload,
        )
        response.raise_for_status()
        
        data = response.json()
        
        if "choices" in data and len(data["choices"]) > 0:
            choice = data["choices"][0]
            if "message" in choice:
                return choice["message"].get("content", "")
            elif "text" in choice:
                return choice["text"]
        
        return str(data)
    
    async def close(self):
        """Закрыть async клиент."""
        if hasattr(self, "_async_client") and self._async_client:
            await self._async_client.aclose()
    
    def __del__(self):
        """Cleanup."""
        # Async client должен быть закрыт через await close()
        pass
