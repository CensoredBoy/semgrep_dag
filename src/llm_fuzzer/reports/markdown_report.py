"""
MarkdownReportGenerator - генератор Markdown отчётов.
"""

from datetime import datetime
from pathlib import Path
from typing import List, Optional

from llm_fuzzer.core.contracts import ReportGenerator
from llm_fuzzer.core.target import TargetConfig
from llm_fuzzer.core.check import CheckResult, CheckStatus, Severity
from llm_fuzzer.core.report import ScanSummary, create_summary


class MarkdownReportGenerator(ReportGenerator):
    """
    Генератор отчётов в формате Markdown.
    
    Создаёт читаемый отчёт для людей с таблицами и форматированием.
    """
    
    # Эмодзи для статусов
    STATUS_EMOJI = {
        CheckStatus.PASSED: "✅",
        CheckStatus.FAILED: "❌",
        CheckStatus.ERROR: "⚠️",
        CheckStatus.SKIPPED: "⏭️",
    }
    
    SEVERITY_EMOJI = {
        Severity.CRITICAL: "🔴",
        Severity.HIGH: "🟠",
        Severity.MEDIUM: "🟡",
        Severity.LOW: "🟢",
    }
    
    @property
    def format(self) -> str:
        return "markdown"
    
    @property
    def file_extension(self) -> str:
        return ".md"
    
    def generate(
        self,
        target: TargetConfig,
        results: List[CheckResult],
        output_path: Optional[Path] = None,
        scan_started: Optional[datetime] = None,
        scan_completed: Optional[datetime] = None,
    ) -> str:
        """
        Сгенерировать Markdown отчёт.
        
        Args:
            target: Конфигурация таргета
            results: Результаты проверок
            output_path: Путь для сохранения
            scan_started: Время начала сканирования
            scan_completed: Время завершения
            
        Returns:
            Markdown строка
        """
        now = datetime.utcnow()
        started = scan_started or now
        completed = scan_completed or now
        
        # Создаём сводку
        summary = create_summary(target, results, started, completed)
        
        # Формируем отчёт
        lines = []
        
        # Заголовок
        lines.append("# LLM Security Scan Report")
        lines.append("")
        lines.append(f"**Generated:** {now.strftime('%Y-%m-%d %H:%M:%S')} UTC")
        lines.append("")
        
        # Информация о таргете
        lines.append("## Target Information")
        lines.append("")
        lines.append(f"| Property | Value |")
        lines.append("|----------|-------|")
        lines.append(f"| Name | {target.name} |")
        lines.append(f"| Endpoint | `{target.endpoint}` |")
        lines.append(f"| Model | {target.model} |")
        lines.append(f"| Type | {target.type} |")
        lines.append("")
        
        # Сводка
        lines.append("## Summary")
        lines.append("")
        lines.append(self._generate_summary_section(summary))
        lines.append("")
        
        # Результаты по категориям
        lines.append("## Results by Category")
        lines.append("")
        
        # Группируем по категориям
        categories = {}
        for r in results:
            cat = r.category
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(r)
        
        for category, cat_results in sorted(categories.items()):
            lines.append(f"### {category.title()}")
            lines.append("")
            lines.append(self._generate_results_table(cat_results))
            lines.append("")
        
        # Детали уязвимостей
        failed_results = [r for r in results if r.status == CheckStatus.FAILED]
        if failed_results:
            lines.append("## Vulnerability Details")
            lines.append("")
            
            for result in failed_results:
                lines.append(f"### {self.SEVERITY_EMOJI.get(result.severity, '')} {result.check_name}")
                lines.append("")
                lines.append(f"**Severity:** {result.severity.upper()}")
                lines.append(f"**Category:** {result.category}")
                lines.append(f"**Engine:** {result.engine_used}")
                lines.append("")
                
                for i, finding in enumerate(result.findings[:5], 1):
                    lines.append(f"#### Finding {i}")
                    lines.append("")
                    lines.append("**Prompt:**")
                    lines.append("```")
                    lines.append(finding.prompt[:300])
                    lines.append("```")
                    lines.append("")
                    lines.append("**Response:**")
                    lines.append("```")
                    lines.append(finding.response[:400])
                    lines.append("```")
                    lines.append("")
                    if finding.evidence:
                        lines.append(f"**Evidence:** {finding.evidence}")
                        lines.append("")
                    lines.append(f"**Confidence:** {finding.confidence:.0%}")
                    lines.append("")
                
                if len(result.findings) > 5:
                    lines.append(f"*... and {len(result.findings) - 5} more findings*")
                    lines.append("")
        
        # Ошибки
        error_results = [r for r in results if r.status == CheckStatus.ERROR]
        if error_results:
            lines.append("## Errors")
            lines.append("")
            for result in error_results:
                lines.append(f"- **{result.check_name}**: {result.error_message}")
            lines.append("")
        
        # Футер
        lines.append("---")
        lines.append("")
        lines.append("*Report generated by [LLM Fuzzer](https://github.com/your-org/llm-fuzzer)*")
        
        content = "\n".join(lines)
        
        if output_path:
            self.save(content, output_path)
        
        return content
    
    def _generate_summary_section(self, summary: ScanSummary) -> str:
        """Сгенерировать секцию сводки."""
        lines = []
        
        # Статистика
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Duration | {summary.duration_seconds:.1f}s |")
        lines.append(f"| Total Checks | {summary.total_checks} |")
        lines.append(f"| ✅ Passed | {summary.passed_checks} |")
        lines.append(f"| ❌ Failed | {summary.failed_checks} |")
        lines.append(f"| ⚠️ Errors | {summary.error_checks} |")
        lines.append(f"| ⏭️ Skipped | {summary.skipped_checks} |")
        lines.append("")
        
        # Findings
        if summary.total_findings > 0:
            lines.append("### Findings by Severity")
            lines.append("")
            lines.append("| Severity | Count |")
            lines.append("|----------|-------|")
            lines.append(f"| 🔴 Critical | {summary.critical_findings} |")
            lines.append(f"| 🟠 High | {summary.high_findings} |")
            lines.append(f"| 🟡 Medium | {summary.medium_findings} |")
            lines.append(f"| 🟢 Low | {summary.low_findings} |")
        
        return "\n".join(lines)
    
    def _generate_results_table(self, results: List[CheckResult]) -> str:
        """Сгенерировать таблицу результатов."""
        lines = []
        
        lines.append("| Status | Check | Severity | Engine | Duration | Findings |")
        lines.append("|--------|-------|----------|--------|----------|----------|")
        
        for r in results:
            status = self.STATUS_EMOJI.get(r.status, "❓")
            severity = self.SEVERITY_EMOJI.get(r.severity, "")
            lines.append(
                f"| {status} | {r.check_name} | {severity} {r.severity} | "
                f"{r.engine_used} | {r.duration_seconds:.1f}s | {r.findings_count} |"
            )
        
        return "\n".join(lines)
    
    def save(self, content: str, output_path: Path) -> None:
        """Сохранить отчёт в файл."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
