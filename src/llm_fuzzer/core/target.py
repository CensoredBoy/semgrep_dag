"""
TargetConfig - конфигурация целевого LLM endpoint.
"""

from enum import Enum
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, SecretStr


class TargetType(str, Enum):
    """Типы поддерживаемых LLM endpoint-ов."""
    OPENAI = "openai"
    AZURE = "azure"
    CUSTOM = "custom"
    HUGGINGFACE = "huggingface"
    LOCAL = "local"


class TargetConfig(BaseModel):
    """
    Конфигурация целевого LLM endpoint для тестирования.
    
    Attributes:
        name: Уникальное имя таргета
        endpoint: URL API endpoint
        api_key: API ключ (SecretStr для безопасности)
        model: Название модели
        type: Тип endpoint-а
        system_prompt: System prompt для тестирования (опционально)
        options: Дополнительные опции (SSL, timeout, headers и т.д.)
    """
    
    name: str = Field(..., description="Уникальное имя таргета")
    endpoint: str = Field(..., description="URL API endpoint")
    api_key: SecretStr = Field(..., description="API ключ")
    model: str = Field(..., description="Название модели")
    type: TargetType = Field(default=TargetType.OPENAI, description="Тип endpoint-а")
    system_prompt: Optional[str] = Field(
        default=None, 
        description="System prompt для тестирования"
    )
    options: Dict[str, Any] = Field(
        default_factory=dict,
        description="Дополнительные опции"
    )
    
    @property
    def disable_ssl_verify(self) -> bool:
        """Проверить, отключена ли SSL верификация."""
        return self.options.get("disable_ssl_verify", False)
    
    @property
    def timeout(self) -> int:
        """Получить таймаут запросов."""
        return self.options.get("timeout", 60)
    
    @property
    def headers(self) -> Dict[str, str]:
        """Получить дополнительные headers."""
        return self.options.get("headers", {})
    
    def get_api_key(self) -> str:
        """Получить API ключ как строку."""
        return self.api_key.get_secret_value()
    
    class Config:
        use_enum_values = True
        
    @classmethod
    def from_yaml(cls, path: str) -> "TargetConfig":
        """Загрузить конфигурацию из YAML файла."""
        import yaml
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls(**data)
    
    def to_yaml(self, path: str) -> None:
        """Сохранить конфигурацию в YAML файл."""
        import yaml
        data = self.model_dump(mode="json")
        # Скрываем API ключ
        data["api_key"] = "***"
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True)
