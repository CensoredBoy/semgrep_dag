"""
JSONReportGenerator - генератор JSON отчётов.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from llm_fuzzer.core.contracts import ReportGenerator
from llm_fuzzer.core.target import TargetConfig
from llm_fuzzer.core.check import CheckResult, CheckStatus
from llm_fuzzer.core.report import ScanSummary, create_summary


class JSONReportGenerator(ReportGenerator):
    """
    Генератор отчётов в формате JSON.
    
    Создаёт структурированный JSON отчёт с полными данными
    для программной обработки.
    """
    
    @property
    def format(self) -> str:
        return "json"
    
    @property
    def file_extension(self) -> str:
        return ".json"
    
    def generate(
        self,
        target: TargetConfig,
        results: List[CheckResult],
        output_path: Optional[Path] = None,
        scan_started: Optional[datetime] = None,
        scan_completed: Optional[datetime] = None,
    ) -> str:
        """
        Сгенерировать JSON отчёт.
        
        Args:
            target: Конфигурация таргета
            results: Результаты проверок
            output_path: Путь для сохранения
            scan_started: Время начала сканирования
            scan_completed: Время завершения
            
        Returns:
            JSON строка
        """
        now = datetime.utcnow()
        started = scan_started or now
        completed = scan_completed or now
        
        # Создаём сводку
        summary = create_summary(target, results, started, completed)
        
        # Формируем отчёт
        report = {
            "meta": {
                "version": "1.0",
                "generated_at": now.isoformat(),
                "generator": "llm-fuzzer",
            },
            "target": {
                "name": target.name,
                "endpoint": target.endpoint,
                "model": target.model,
                "type": target.type,
            },
            "summary": {
                "scan_started": started.isoformat(),
                "scan_completed": completed.isoformat(),
                "duration_seconds": summary.duration_seconds,
                "total_checks": summary.total_checks,
                "passed": summary.passed_checks,
                "failed": summary.failed_checks,
                "errors": summary.error_checks,
                "skipped": summary.skipped_checks,
                "total_findings": summary.total_findings,
                "findings_by_severity": {
                    "critical": summary.critical_findings,
                    "high": summary.high_findings,
                    "medium": summary.medium_findings,
                    "low": summary.low_findings,
                },
                "success_rate": round(summary.success_rate, 2),
                "vulnerability_rate": round(summary.vulnerability_rate, 2),
                "engines_used": summary.engines_used,
            },
            "results": [
                self._serialize_result(r) for r in results
            ],
        }
        
        content = json.dumps(report, indent=2, ensure_ascii=False, default=str)
        
        if output_path:
            self.save(content, output_path)
        
        return content
    
    def _serialize_result(self, result: CheckResult) -> dict:
        """Сериализовать результат проверки."""
        return {
            "check_id": result.check_id,
            "check_name": result.check_name,
            "category": result.category,
            "status": result.status,
            "severity": result.severity,
            "engine_used": result.engine_used,
            "duration_seconds": round(result.duration_seconds, 3),
            "started_at": result.started_at.isoformat(),
            "findings_count": result.findings_count,
            "findings": [
                {
                    "prompt": f.prompt[:200] + "..." if len(f.prompt) > 200 else f.prompt,
                    "response": f.response[:300] + "..." if len(f.response) > 300 else f.response,
                    "evidence": f.evidence,
                    "confidence": f.confidence,
                    "metadata": f.metadata,
                }
                for f in result.findings
            ],
            "error_message": result.error_message,
        }
    
    def save(self, content: str, output_path: Path) -> None:
        """Сохранить отчёт в файл."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
