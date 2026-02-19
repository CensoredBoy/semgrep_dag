"""
ScanEngine -- top-level coordinator for scanning using PyRIT.

Orchestrates:
1. Initializing PyRIT memory (IN_MEMORY)
2. Creating PyRIT OpenAIChatTarget instances (with verify=False)
3. Loading attacks from DB and resolving into AttackPipeline DTOs
4. Running each attack via AttackRunner (backed by PyRIT orchestrators)
5. Aggregating results into ScanResultDTO
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from sqlalchemy.orm import Session

from scanner.catalogs.catalogs import AttackCatalog
from scanner.config import TargetConfig
from scanner.data.models import Attack
from scanner.engine.attack_pipeline import AttackPipeline, PromptDTO, ToolDTO
from scanner.engine.runner import AttackRunDTO, AttackRunner
from scanner.pyrit_adapter.target_factory import create_target

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Scan Result DTO
# ---------------------------------------------------------------------------


@dataclass
class ScanResultDTO:
    """Aggregated result of a full scan session."""

    session_id: str = ""
    target_url: str = ""
    target_model: str = ""
    mode: str = "simple"
    attack_runs: list[AttackRunDTO] = field(default_factory=list)
    total_attacks: int = 0
    total_prompts: int = 0
    total_hits: int = 0
    overall_success_rate: float = 0.0
    started_at: float = 0.0
    finished_at: float = 0.0
    duration_seconds: float = 0.0


# ---------------------------------------------------------------------------
# Pipeline builder (Attack ORM → AttackPipeline DTO)
# ---------------------------------------------------------------------------


def _build_pipeline(attack: Attack) -> AttackPipeline:
    """Convert an Attack ORM entity to an AttackPipeline DTO."""
    prompts = [
        PromptDTO(id=p.id, content=p.content)
        for p in attack.prompts
        if p.is_active
    ]

    tools = [
        ToolDTO(
            name=t.name,
            description=t.description,
            parameters_schema=(
                json.loads(t.parameters_schema)
                if isinstance(t.parameters_schema, str)
                else t.parameters_schema
            ),
        )
        for t in attack.tools
        if t.is_active
    ]

    detector_substrings = [
        ds.substring
        for ds in attack.detector_substrings
        if ds.is_active
    ]

    judge_system_prompt = None
    judge_true_description = None
    if attack.judge_instruction:
        judge_system_prompt = attack.judge_instruction.system_prompt
        judge_true_description = attack.judge_instruction.true_description

    attacker_system_prompt = None
    if attack.attacker_instruction:
        attacker_system_prompt = attack.attacker_instruction.system_prompt

    converter_chain = (
        json.loads(attack.converter_chain)
        if isinstance(attack.converter_chain, str)
        else attack.converter_chain
    )

    return AttackPipeline(
        attack_id=attack.id,
        name=attack.name,
        category=attack.category,
        orchestrator_type=attack.orchestrator_type,
        scorer_type=attack.scorer_type,
        prompts=prompts,
        tools=tools,
        detector_substrings=detector_substrings,
        detector_is_negation=attack.is_negation,
        judge_system_prompt=judge_system_prompt,
        judge_true_description=judge_true_description,
        attacker_system_prompt=attacker_system_prompt,
        converter_names=converter_chain,
        max_turns=attack.max_turns,
    )


# ---------------------------------------------------------------------------
# PyRIT initialization
# ---------------------------------------------------------------------------


async def _init_pyrit() -> None:
    """Initialize PyRIT with in-memory storage (no persistent DB)."""
    from pyrit.setup import IN_MEMORY, initialize_pyrit_async
    await initialize_pyrit_async(memory_db_type=IN_MEMORY, silent=True)


# ---------------------------------------------------------------------------
# ScanEngine
# ---------------------------------------------------------------------------


class ScanEngine:
    """
    Top-level scan coordinator using PyRIT as the core engine.

    Creates PyRIT OpenAIChatTargets with SSL verification disabled
    and delegates attack execution to PyRIT orchestrators.

    Usage:
        engine = ScanEngine(session, target_cfg)
        result = await engine.run_simple_async(["jailbreak_basic"])
    """

    def __init__(
        self,
        session: Session,
        target_config: TargetConfig,
        attacker_config: Optional[TargetConfig] = None,
        judge_config: Optional[TargetConfig] = None,
    ) -> None:
        self.session = session
        self.attack_catalog = AttackCatalog(session)
        self.target_config = target_config
        self.attacker_config = attacker_config
        self.judge_config = judge_config

        # PyRIT targets (created lazily in async context)
        self._target = None
        self._attacker = None
        self._judge = None
        self._runner = None

    async def _ensure_initialized(self) -> None:
        """Initialize PyRIT and create targets (called once)."""
        if self._target is not None:
            return

        # Initialize PyRIT in-memory
        await _init_pyrit()

        # Create PyRIT targets
        self._target = create_target(self.target_config)
        self._attacker = create_target(self.attacker_config) if self.attacker_config else None
        self._judge = create_target(self.judge_config) if self.judge_config else None

        self._runner = AttackRunner(
            target=self._target,
            target_config=self.target_config,
            attacker=self._attacker,
            judge=self._judge,
        )

    # ------ Simple mode (sync wrapper) ------

    def run_simple(
        self,
        attack_names: list[str],
        max_prompts_per_attack: int = 100,
    ) -> ScanResultDTO:
        """Simple mode (sync): run predefined attacks by name."""
        return asyncio.run(self.run_simple_async(attack_names, max_prompts_per_attack))

    def run_by_category(
        self,
        categories: list[str],
        max_prompts_per_attack: int = 100,
    ) -> ScanResultDTO:
        """Run all active attacks in given categories (sync)."""
        return asyncio.run(self.run_by_category_async(categories, max_prompts_per_attack))

    def run_advanced(
        self,
        attacks: list[Attack],
        max_prompts_per_attack: int = 100,
    ) -> ScanResultDTO:
        """Advanced mode (sync): run a custom list of Attack entities."""
        return asyncio.run(self.run_advanced_async(attacks, max_prompts_per_attack))

    # ------ Async implementations ------

    async def run_simple_async(
        self,
        attack_names: list[str],
        max_prompts_per_attack: int = 100,
    ) -> ScanResultDTO:
        """Simple mode: run predefined attacks by name."""
        attacks = self.attack_catalog.get_by_names(attack_names)
        if not attacks:
            logger.error("No attacks found with names: %s", attack_names)
            return ScanResultDTO(mode="simple")
        return await self._execute_attacks(attacks, "simple", max_prompts_per_attack)

    async def run_by_category_async(
        self,
        categories: list[str],
        max_prompts_per_attack: int = 100,
    ) -> ScanResultDTO:
        """Run all active attacks in given categories."""
        attacks: list[Attack] = []
        for cat in categories:
            attacks.extend(self.attack_catalog.list_all(category=cat))
        return await self._execute_attacks(attacks, "simple", max_prompts_per_attack)

    async def run_advanced_async(
        self,
        attacks: list[Attack],
        max_prompts_per_attack: int = 100,
    ) -> ScanResultDTO:
        """Advanced mode: run a custom list of Attack entities."""
        return await self._execute_attacks(attacks, "advanced", max_prompts_per_attack)

    # ------ Core execution ------

    async def _execute_attacks(
        self,
        attacks: list[Attack],
        mode: str,
        max_prompts: int,
    ) -> ScanResultDTO:
        """Core execution loop using PyRIT."""
        await self._ensure_initialized()

        scan = ScanResultDTO(
            session_id=str(uuid.uuid4()),
            target_url=self.target_config.url,
            target_model=self.target_config.model,
            mode=mode,
            started_at=time.time(),
        )

        for attack in attacks:
            logger.info("Running attack: %s [%s]", attack.name, attack.category)

            pipeline = _build_pipeline(attack)

            # Truncate prompts if needed
            if len(pipeline.prompts) > max_prompts:
                pipeline.prompts = pipeline.prompts[:max_prompts]

            # Execute via PyRIT-backed runner
            run_result = await self._runner.run_async(pipeline)
            scan.attack_runs.append(run_result)

            logger.info(
                "Attack %s: %d/%d hits (%.1f%%)",
                attack.name,
                run_result.successful_hits,
                run_result.total_prompts,
                run_result.success_rate * 100,
            )

        # Aggregate
        scan.total_attacks = len(scan.attack_runs)
        scan.total_prompts = sum(r.total_prompts for r in scan.attack_runs)
        scan.total_hits = sum(r.successful_hits for r in scan.attack_runs)
        scan.overall_success_rate = (
            scan.total_hits / scan.total_prompts if scan.total_prompts > 0 else 0.0
        )
        scan.finished_at = time.time()
        scan.duration_seconds = scan.finished_at - scan.started_at

        return scan
