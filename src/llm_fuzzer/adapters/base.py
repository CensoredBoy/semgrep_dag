"""
BaseAdapter - базовый класс для всех адаптеров.
"""

import logging
import time
from abc import ABC, abstractmethod
from typing import List, Optional
from datetime import datetime

from llm_fuzzer.core.contracts import ScannerAdapter
from llm_fuzzer.core.target import TargetConfig
from llm_fuzzer.core.check import (
    CheckConfig, 
    CheckResult, 
    CheckStatus,
    Finding,
)

logger = logging.getLogger(__name__)


class BaseAdapter(ScannerAdapter, ABC):
    """
    Базовый класс для адаптеров сканирования.
    
    Предоставляет общую логику для всех адаптеров:
    - Логирование
    - Обработка ошибок
    - Измерение времени выполнения
    """
    
    def __init__(self):
        self._initialized = False
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    async def run_checks(
        self, 
        target: TargetConfig, 
        checks: List[CheckConfig]
    ) -> List[CheckResult]:
        """
        Выполнить несколько проверок последовательно.
        
        Args:
            target: Конфигурация таргета
            checks: Список проверок
            
        Returns:
            Список результатов
        """
        results = []
        
        for check in checks:
            if not check.enabled:
                self._logger.info(f"Skipping disabled check: {check.id}")
                continue
                
            if not self.supports_check(check):
                self._logger.warning(
                    f"Check {check.id} not supported by {self.name}, skipping"
                )
                result = CheckResult(
                    check_id=check.id,
                    check_name=check.name,
                    category=check.category,
                    status=CheckStatus.SKIPPED,
                    severity=check.severity,
                    engine_used=self.name,
                    duration_seconds=0.0,
                    error_message=f"Not supported by {self.name}",
                )
                results.append(result)
                continue
            
            try:
                self._logger.info(f"Running check: {check.id} ({check.name})")
                result = await self.run_check(target, check)
                results.append(result)
                
                if result.status == CheckStatus.FAILED:
                    self._logger.warning(
                        f"Check {check.id} FAILED: {result.findings_count} findings"
                    )
                else:
                    self._logger.info(f"Check {check.id} completed: {result.status}")
                    
            except Exception as e:
                self._logger.error(f"Error running check {check.id}: {e}")
                result = CheckResult(
                    check_id=check.id,
                    check_name=check.name,
                    category=check.category,
                    status=CheckStatus.ERROR,
                    severity=check.severity,
                    engine_used=self.name,
                    duration_seconds=0.0,
                    error_message=str(e),
                )
                results.append(result)
        
        return results
    
    def _create_error_result(
        self, 
        check: CheckConfig, 
        error: Exception,
        duration: float = 0.0
    ) -> CheckResult:
        """Создать результат с ошибкой."""
        return CheckResult(
            check_id=check.id,
            check_name=check.name,
            category=check.category,
            status=CheckStatus.ERROR,
            severity=check.severity,
            engine_used=self.name,
            duration_seconds=duration,
            error_message=str(error),
        )
    
    def _create_passed_result(
        self,
        check: CheckConfig,
        duration: float,
        raw_output: dict = None
    ) -> CheckResult:
        """Создать успешный результат (уязвимость не найдена)."""
        return CheckResult(
            check_id=check.id,
            check_name=check.name,
            category=check.category,
            status=CheckStatus.PASSED,
            severity=check.severity,
            engine_used=self.name,
            duration_seconds=duration,
            raw_output=raw_output or {},
        )
    
    def _create_failed_result(
        self,
        check: CheckConfig,
        findings: List[Finding],
        duration: float,
        raw_output: dict = None
    ) -> CheckResult:
        """Создать результат с найденными уязвимостями."""
        return CheckResult(
            check_id=check.id,
            check_name=check.name,
            category=check.category,
            status=CheckStatus.FAILED,
            severity=check.severity,
            findings=findings,
            engine_used=self.name,
            duration_seconds=duration,
            raw_output=raw_output or {},
        )
