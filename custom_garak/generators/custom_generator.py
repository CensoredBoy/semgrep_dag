"""
Custom Garak Generator - Пример кастомного generator для garak.

Generators - это адаптеры для LLM, которые garak использует
для отправки prompts и получения ответов.
"""

import os
from typing import List, Union
import httpx

# Пытаемся импортировать garak, но не падаем если его нет
try:
    from garak.generators.base import Generator
except ImportError:
    # Fallback для разработки без garak
    class Generator:
        def __init__(self, name="", generations=1):
            self.name = name
            self.generations = generations


class CustomOpenAIGenerator(Generator):
    """
    Кастомный generator для OpenAI-совместимых API.
    
    Поддерживает:
    - Кастомные endpoint-ы
    - Отключение SSL верификации
    - Дополнительные headers
    """
    
    name = "custom_openai"
    description = "Custom OpenAI-compatible API generator"
    
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
        disable_ssl_verify: bool = False,
        extra_headers: dict = None,
    ):
        """
        Инициализация generator.
        
        Args:
            name: Имя generator
            generations: Количество генераций на запрос
            endpoint: URL API endpoint
            api_key: API ключ
            model: Название модели
            disable_ssl_verify: Отключить SSL верификацию
            extra_headers: Дополнительные HTTP headers
        """
        super().__init__(name or self.name, generations)
        
        self.endpoint = endpoint or os.getenv(
            "OPENAI_API_BASE", 
            "https://api.openai.com/v1/chat/completions"
        )
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self.model = model
        self.disable_ssl_verify = disable_ssl_verify
        self.extra_headers = extra_headers or {}
        
        # Создаём HTTP клиент
        self._client = httpx.Client(
            verify=not disable_ssl_verify,
            timeout=60.0,
        )
    
    def generate(
        self, 
        prompt: Union[str, List[str]],
        generations_this_call: int = None,
    ) -> List[str]:
        """
        Сгенерировать ответы для prompt(s).
        
        Args:
            prompt: Один prompt или список
            generations_this_call: Количество генераций
            
        Returns:
            Список сгенерированных ответов
        """
        if isinstance(prompt, str):
            prompts = [prompt]
        else:
            prompts = prompt
        
        n = generations_this_call or self.generations
        outputs = []
        
        for p in prompts:
            for _ in range(n):
                try:
                    response = self._call_api(p)
                    outputs.append(response)
                except Exception as e:
                    outputs.append(f"Error: {e}")
        
        return outputs
    
    def _call_api(self, prompt: str) -> str:
        """Вызвать API и получить ответ."""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            **self.extra_headers,
        }
        
        payload = {
            "model": self.model,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            **self.DEFAULT_PARAMS,
        }
        
        response = self._client.post(
            self.endpoint,
            headers=headers,
            json=payload,
        )
        response.raise_for_status()
        
        data = response.json()
        return data["choices"][0]["message"]["content"]
    
    def __del__(self):
        """Закрыть HTTP клиент."""
        if hasattr(self, "_client"):
            self._client.close()


class CustomLocalGenerator(Generator):
    """
    Generator для локальных моделей (Ollama, vLLM, etc).
    """
    
    name = "custom_local"
    description = "Generator for local LLM servers"
    
    def __init__(
        self,
        name: str = "",
        generations: int = 1,
        endpoint: str = "http://localhost:11434/api/generate",  # Ollama default
        model: str = "llama2",
    ):
        super().__init__(name or self.name, generations)
        self.endpoint = endpoint
        self.model = model
        self._client = httpx.Client(timeout=120.0)
    
    def generate(
        self, 
        prompt: Union[str, List[str]],
        generations_this_call: int = None,
    ) -> List[str]:
        if isinstance(prompt, str):
            prompts = [prompt]
        else:
            prompts = prompt
        
        n = generations_this_call or self.generations
        outputs = []
        
        for p in prompts:
            for _ in range(n):
                try:
                    response = self._call_ollama(p)
                    outputs.append(response)
                except Exception as e:
                    outputs.append(f"Error: {e}")
        
        return outputs
    
    def _call_ollama(self, prompt: str) -> str:
        """Вызвать Ollama API."""
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }
        
        response = self._client.post(self.endpoint, json=payload)
        response.raise_for_status()
        
        return response.json().get("response", "")
    
    def __del__(self):
        if hasattr(self, "_client"):
            self._client.close()
