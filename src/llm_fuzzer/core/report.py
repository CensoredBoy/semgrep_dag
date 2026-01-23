"""
ReportGenerator - базовый класс для генерации отчётов.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field

from .target import TargetConfig
from .check import CheckResult, CheckStatus, Severity


@dataclass
class ScanSummary:
    """
    Сводка результатов сканирования.
    """
    
    target_name: str
    target_endpoint: str
    target_model: str
    scan_started: datetime
    scan_completed: datetime
    total_checks: int
    passed_checks: int
    failed_checks: int
    error_checks: int
    skipped_checks: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    engines_used: List[str] = field(default_factory=list)
    
    @property
    def duration_seconds(self) -> float:
        """Общая длительность сканирования."""
        return (self.scan_completed - self.scan_started).total_seconds()
    
    @property
    def success_rate(self) -> float:
        """Процент успешных проверок."""
        if self.total_checks == 0:
            return 0.0
        return (self.passed_checks / self.total_checks) * 100
    
    @property
    def vulnerability_rate(self) -> float:
        """Процент проверок с найденными уязвимостями."""
        if self.total_checks == 0:
            return 0.0
        return (self.failed_checks / self.total_checks) * 100


def create_summary(
    target: TargetConfig,
    results: List[CheckResult],
    scan_started: datetime,
    scan_completed: datetime
) -> ScanSummary:
    """
    Создать сводку из результатов сканирования.
    
    Args:
        target: Конфигурация таргета
        results: Результаты проверок
        scan_started: Время начала
        scan_completed: Время завершения
        
    Returns:
        Сводка сканирования
    """
    # Считаем статусы
    passed = sum(1 for r in results if r.status == CheckStatus.PASSED)
    failed = sum(1 for r in results if r.status == CheckStatus.FAILED)
    errors = sum(1 for r in results if r.status == CheckStatus.ERROR)
    skipped = sum(1 for r in results if r.status == CheckStatus.SKIPPED)
    
    # Считаем findings по severity
    all_findings = [f for r in results for f in r.findings]
    critical = sum(1 for r in results if r.severity == Severity.CRITICAL and r.findings)
    high = sum(1 for r in results if r.severity == Severity.HIGH and r.findings)
    medium = sum(1 for r in results if r.severity == Severity.MEDIUM and r.findings)
    low = sum(1 for r in results if r.severity == Severity.LOW and r.findings)
    
    # Собираем использованные движки
    engines = list(set(r.engine_used for r in results))
    
    return ScanSummary(
        target_name=target.name,
        target_endpoint=target.endpoint,
        target_model=target.model,
        scan_started=scan_started,
        scan_completed=scan_completed,
        total_checks=len(results),
        passed_checks=passed,
        failed_checks=failed,
        error_checks=errors,
        skipped_checks=skipped,
        total_findings=len(all_findings),
        critical_findings=critical,
        high_findings=high,
        medium_findings=medium,
        low_findings=low,
        engines_used=engines,
    )
