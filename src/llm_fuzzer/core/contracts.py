"""
Абстрактные интерфейсы (контракты) для компонентов системы.
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from pathlib import Path

from .target import TargetConfig
from .check import CheckConfig, CheckResult


class ScannerAdapter(ABC):
    """
    Абстрактный интерфейс для адаптеров сканирования.
    
    Все адаптеры (Garak, PyRIT) должны реализовывать этот интерфейс,
    что позволяет унифицировать работу с разными движками.
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Название движка."""
        pass
    
    @property
    @abstractmethod
    def version(self) -> str:
        """Версия движка."""
        pass
    
    @abstractmethod
    async def initialize(self) -> None:
        """
        Инициализация адаптера.
        
        Вызывается один раз перед началом сканирования.
        """
        pass
    
    @abstractmethod
    async def run_check(
        self, 
        target: TargetConfig, 
        check: CheckConfig
    ) -> CheckResult:
        """
        Выполнить одну проверку безопасности.
        
        Args:
            target: Конфигурация целевого endpoint
            check: Конфигурация проверки
            
        Returns:
            Результат проверки
        """
        pass
    
    @abstractmethod
    async def run_checks(
        self, 
        target: TargetConfig, 
        checks: List[CheckConfig]
    ) -> List[CheckResult]:
        """
        Выполнить несколько проверок.
        
        Args:
            target: Конфигурация целевого endpoint
            checks: Список проверок
            
        Returns:
            Список результатов
        """
        pass
    
    @abstractmethod
    def supports_check(self, check: CheckConfig) -> bool:
        """
        Проверить, поддерживает ли адаптер данную проверку.
        
        Args:
            check: Конфигурация проверки
            
        Returns:
            True если проверка поддерживается
        """
        pass
    
    @abstractmethod
    async def cleanup(self) -> None:
        """
        Очистка ресурсов после сканирования.
        """
        pass


class ReportGenerator(ABC):
    """
    Абстрактный интерфейс для генераторов отчётов.
    """
    
    @property
    @abstractmethod
    def format(self) -> str:
        """Формат отчёта (json, md, html и т.д.)."""
        pass
    
    @property
    @abstractmethod
    def file_extension(self) -> str:
        """Расширение файла."""
        pass
    
    @abstractmethod
    def generate(
        self,
        target: TargetConfig,
        results: List[CheckResult],
        output_path: Optional[Path] = None
    ) -> str:
        """
        Сгенерировать отчёт.
        
        Args:
            target: Конфигурация таргета
            results: Результаты проверок
            output_path: Путь для сохранения (опционально)
            
        Returns:
            Содержимое отчёта как строка
        """
        pass
    
    @abstractmethod
    def save(
        self,
        content: str,
        output_path: Path
    ) -> None:
        """
        Сохранить отчёт в файл.
        
        Args:
            content: Содержимое отчёта
            output_path: Путь для сохранения
        """
        pass


class ScanEngine(ABC):
    """
    Высокоуровневый интерфейс движка сканирования.
    
    Координирует работу адаптеров и генерирует отчёты.
    """
    
    @abstractmethod
    async def scan(
        self,
        target: TargetConfig,
        checks: List[CheckConfig],
        output_dir: Optional[Path] = None,
        formats: Optional[List[str]] = None
    ) -> List[CheckResult]:
        """
        Выполнить полное сканирование.
        
        Args:
            target: Конфигурация таргета
            checks: Список проверок
            output_dir: Директория для отчётов
            formats: Форматы отчётов (md, json)
            
        Returns:
            Список результатов всех проверок
        """
        pass
