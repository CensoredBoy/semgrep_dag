"""
Report generators -- Markdown and JSON.

Generates human-readable Markdown and full JSON log from ScanResultDTO.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scanner.engine.runner import AttackRunDTO
from scanner.engine.scan_engine import ScanResultDTO

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# JSON Report
# ---------------------------------------------------------------------------


def _default_serializer(obj: Any) -> Any:
    """Handle non-serializable types."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, float) and (obj != obj):  # NaN check
        return 0.0
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def generate_json_report(scan_result: ScanResultDTO, output_path: str | Path) -> Path:
    """
    Generate full JSON log from scan results.

    Contains every prompt, response, tool_calls, verdict, and score.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = asdict(scan_result)
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False, default=_default_serializer),
        encoding="utf-8",
    )
    logger.info("JSON report written to %s", path)
    return path


# ---------------------------------------------------------------------------
# Markdown Report
# ---------------------------------------------------------------------------


def _format_pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def _pick_examples(run: AttackRunDTO, max_examples: int = 4) -> list[dict[str, str]]:
    """Pick up to N successful hit examples from an attack run."""
    hits = [r for r in run.results if r.is_hit]
    examples = []
    for r in hits[:max_examples]:
        example: dict[str, str] = {
            "prompt": r.original_prompt[:300],
            "response": r.response[:500] if r.response else "(empty)",
        }
        if r.response_tool_calls:
            example["tool_calls"] = json.dumps(r.response_tool_calls, indent=2, ensure_ascii=False)[:500]
        if r.judge_reasoning:
            example["judge_reasoning"] = r.judge_reasoning[:300]
        examples.append(example)
    return examples


def generate_md_report(scan_result: ScanResultDTO, output_path: str | Path) -> Path:
    """
    Generate human-readable Markdown report.

    Includes:
    - Summary table with success rates
    - Per-attack breakdown with 3-4 examples of successful hits
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines: list[str] = []

    # Header
    lines.append(f"# LLM Fuzzing Scan Report")
    lines.append("")
    lines.append(f"**Generated:** {ts}  ")
    lines.append(f"**Target:** `{scan_result.target_model}` @ `{scan_result.target_url}`  ")
    lines.append(f"**Mode:** {scan_result.mode}  ")
    lines.append(f"**Duration:** {scan_result.duration_seconds:.1f}s  ")
    lines.append("")

    # Overall summary
    lines.append("## Summary")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total attacks | {scan_result.total_attacks} |")
    lines.append(f"| Total prompts | {scan_result.total_prompts} |")
    lines.append(f"| Total hits | {scan_result.total_hits} |")
    lines.append(f"| Overall success rate | {_format_pct(scan_result.overall_success_rate)} |")
    lines.append("")

    # Per-attack table
    lines.append("## Attack Results")
    lines.append("")
    lines.append("| # | Attack | Category | Prompts | Hits | Success Rate | Duration |")
    lines.append("|---|--------|----------|---------|------|-------------|----------|")
    for i, run in enumerate(scan_result.attack_runs, 1):
        lines.append(
            f"| {i} | {run.attack_name} | {run.category} | "
            f"{run.total_prompts} | {run.successful_hits} | "
            f"{_format_pct(run.success_rate)} | {run.duration_seconds:.1f}s |"
        )
    lines.append("")

    # Per-attack details with examples
    lines.append("## Detailed Results")
    lines.append("")

    for run in scan_result.attack_runs:
        lines.append(f"### {run.attack_name}")
        lines.append("")
        lines.append(f"- **Category:** {run.category}")
        lines.append(f"- **Status:** {run.status}")
        lines.append(f"- **Prompts:** {run.total_prompts}")
        lines.append(f"- **Hits:** {run.successful_hits}")
        lines.append(f"- **Success Rate:** {_format_pct(run.success_rate)}")
        lines.append("")

        examples = _pick_examples(run)
        if examples:
            lines.append("**Successful Hit Examples:**")
            lines.append("")
            for j, ex in enumerate(examples, 1):
                lines.append(f"<details>")
                lines.append(f"<summary>Example {j}</summary>")
                lines.append("")
                lines.append(f"**Prompt:**")
                lines.append(f"```")
                lines.append(ex["prompt"])
                lines.append(f"```")
                lines.append("")
                lines.append(f"**Response:**")
                lines.append(f"```")
                lines.append(ex["response"])
                lines.append(f"```")
                if "tool_calls" in ex:
                    lines.append("")
                    lines.append(f"**Tool Calls:**")
                    lines.append(f"```json")
                    lines.append(ex["tool_calls"])
                    lines.append(f"```")
                if "judge_reasoning" in ex:
                    lines.append("")
                    lines.append(f"**Judge Reasoning:** {ex['judge_reasoning']}")
                lines.append("")
                lines.append(f"</details>")
                lines.append("")
        else:
            lines.append("_No successful hits._")
            lines.append("")

        lines.append("---")
        lines.append("")

    content = "\n".join(lines)
    path.write_text(content, encoding="utf-8")
    logger.info("Markdown report written to %s", path)
    return path
