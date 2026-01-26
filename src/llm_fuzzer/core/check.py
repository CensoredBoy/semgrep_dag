"""
CheckConfig, CheckResult - конфигурация проверок и результаты.
"""

from enum import Enum
from typing import Optional, List, Dict, Any, Literal
from datetime import datetime
from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Уровни серьёзности уязвимостей."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CheckStatus(str, Enum):
    """Статусы выполнения проверок."""
    PASSED = "passed"       # Уязвимость не обнаружена
    FAILED = "failed"       # Уязвимость обнаружена
    ERROR = "error"         # Ошибка при выполнении
    SKIPPED = "skipped"     # Проверка пропущена


class EngineType(str, Enum):
    """Типы движков сканирования."""
    GARAK = "garak"
    PYRIT = "pyrit"
    AUTO = "auto"


class CheckCategory(str, Enum):
    """Категории проверок безопасности."""
    JAILBREAK = "jailbreak"
    INJECTION = "injection"
    LEAKAGE = "leakage"
    TOOL_ABUSE = "tool_abuse"
    TOXICITY = "toxicity"
    BIAS = "bias"
    HALLUCINATION = "hallucination"
    CUSTOM = "custom"


class CheckConfig(BaseModel):
    """
    Конфигурация отдельной проверки безопасности.
    
    Attributes:
        id: Уникальный идентификатор проверки
        name: Человекочитаемое название
        category: Категория проверки
        engine: Предпочтительный движок (garak/pyrit/auto)
        severity: Уровень серьёзности при обнаружении
        enabled: Включена ли проверка
        params: Параметры для движка
    """
    
    id: str = Field(..., description="Уникальный ID проверки")
    name: str = Field(..., description="Название проверки")
    description: Optional[str] = Field(default=None, description="Описание")
    category: CheckCategory = Field(..., description="Категория проверки")
    engine: EngineType = Field(
        default=EngineType.AUTO, 
        description="Предпочтительный движок"
    )
    severity: Severity = Field(
        default=Severity.MEDIUM, 
        description="Уровень серьёзности"
    )
    enabled: bool = Field(default=True, description="Включена ли проверка")
    params: Dict[str, Any] = Field(
        default_factory=dict, 
        description="Параметры для движка"
    )
    
    # Специфичные параметры для garak
    garak_probes: Optional[List[str]] = Field(
        default=None, 
        description="Список garak probes"
    )
    garak_detectors: Optional[List[str]] = Field(
        default=None, 
        description="Список garak detectors"
    )
    
    # Специфичные параметры для PyRIT
    pyrit_scorer: Optional[str] = Field(
        default=None, 
        description="PyRIT scorer class"
    )
    pyrit_attack_type: Optional[str] = Field(
        default=None, 
        description="Тип атаки PyRIT"
    )
    
    # Количество генераций
    generations: int = Field(
        default=1,
        ge=1,
        description="Количество генераций для каждого prompt (повторов атаки)"
    )
    
    # Максимальное количество промптов
    max_prompts: Optional[int] = Field(
        default=None,
        ge=1,
        description="Максимальное количество промптов для проверки (None = все доступные)"
    )
    
    class Config:
        use_enum_values = True


class Finding(BaseModel):
    """
    Отдельная находка (уязвимость) обнаруженная при проверке.
    
    Attributes:
        prompt: Промпт, который вызвал уязвимость
        response: Ответ модели
        evidence: Доказательства уязвимости
        confidence: Уровень уверенности (0-1)
    """
    
    prompt: str = Field(..., description="Атакующий промпт")
    response: str = Field(..., description="Ответ модели")
    evidence: Optional[str] = Field(default=None, description="Доказательства")
    confidence: float = Field(
        default=1.0, 
        ge=0.0, 
        le=1.0, 
        description="Уровень уверенности"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict, 
        description="Дополнительные метаданные"
    )


class CheckResult(BaseModel):
    """
    Результат выполнения проверки безопасности.
    
    Attributes:
        check_id: ID проверки
        check_name: Название проверки
        status: Статус выполнения
        severity: Уровень серьёзности
        findings: Список найденных уязвимостей
        engine_used: Какой движок использовался
        duration_seconds: Время выполнения
        raw_output: Сырой вывод от движка
    """
    
    check_id: str = Field(..., description="ID проверки")
    check_name: str = Field(..., description="Название проверки")
    category: str = Field(..., description="Категория проверки")
    status: CheckStatus = Field(..., description="Статус выполнения")
    severity: Severity = Field(..., description="Уровень серьёзности")
    findings: List[Finding] = Field(
        default_factory=list, 
        description="Найденные уязвимости"
    )
    engine_used: str = Field(..., description="Использованный движок")
    duration_seconds: float = Field(..., description="Время выполнения")
    started_at: datetime = Field(
        default_factory=datetime.utcnow, 
        description="Время начала"
    )
    error_message: Optional[str] = Field(
        default=None, 
        description="Сообщение об ошибке"
    )
    raw_output: Dict[str, Any] = Field(
        default_factory=dict, 
        description="Сырой вывод от движка"
    )
    total_prompts: int = Field(
        default=0,
        description="Всего отправлено промптов"
    )
    successful_attacks: int = Field(
        default=0,
        description="Успешных атак"
    )
    
    @property
    def success_rate(self) -> float:
        """Процент успешных атак (0-100)."""
        if self.total_prompts == 0:
            return 0.0
        return (self.successful_attacks / self.total_prompts) * 100
    
    @property
    def is_vulnerable(self) -> bool:
        """Проверить, обнаружена ли уязвимость."""
        return self.status == CheckStatus.FAILED and len(self.findings) > 0
    
    @property
    def findings_count(self) -> int:
        """Количество найденных уязвимостей."""
        return len(self.findings)
    
    class Config:
        use_enum_values = True


class ChecksConfig(BaseModel):
    """
    Коллекция проверок для загрузки из YAML.
    """
    
    name: str = Field(..., description="Название набора проверок")
    description: Optional[str] = Field(default=None)
    checks: List[CheckConfig] = Field(default_factory=list)
    
    @classmethod
    def from_yaml(cls, path: str) -> "ChecksConfig":
        """Загрузить конфигурацию из YAML файла."""
        import yaml
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls(**data)
    
    def get_enabled_checks(self) -> List[CheckConfig]:
        """Получить только включённые проверки."""
        return [c for c in self.checks if c.enabled]
    
    def filter_by_category(self, category: CheckCategory) -> List[CheckConfig]:
        """Фильтровать проверки по категории."""
        return [c for c in self.checks if c.category == category and c.enabled]
    
    def filter_by_engine(self, engine: EngineType) -> List[CheckConfig]:
        """Фильтровать проверки по движку."""
        return [c for c in self.checks if c.engine == engine and c.enabled]
