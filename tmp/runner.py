"""
AttackRunner -- выполняет атаки через PyRIT. Автономный модуль без зависимостей от проекта.

Поддерживает:
- PromptSendingAttack  (single-turn)
- RedTeamingAttack     (multi-turn)
- SubStringScorer / SelfAskTrueFalseScorer
- OpenAIChatTarget     (обычные запросы)
- ToolEnabledTarget    (tool_abuse: tools в каждом API-запросе)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

import yaml

from pyrit.executor.attack import (
    AttackAdversarialConfig,
    AttackScoringConfig,
    PromptSendingAttack,
    RedTeamingAttack,
)
from pyrit.executor.attack.core.attack_strategy import AttackResult as PyRITAttackResult
from pyrit.executor.attack.core.attack_strategy import AttackOutcome
from pyrit.memory import CentralMemory
from pyrit.prompt_target import OpenAIChatTarget
from pyrit.score.true_false.true_false_scorer import TrueFalseScorer

from target_factory import TargetConfig, create_tool_target
from scorer_factory import create_llm_judge_scorer, create_substring_scorer

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# DTO: конфигурация атаки
# ---------------------------------------------------------------------------


@dataclass
class PromptDTO:
    id: str
    content: str


@dataclass
class ToolDTO:
    name: str
    description: str
    parameters_schema: dict[str, Any]

    def to_openai_tool(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters_schema,
            },
        }


@dataclass
class AttackPipeline:
    attack_id: str
    name: str
    category: str
    orchestrator_type: str      # prompt_sending | red_teaming
    scorer_type: str            # substring | llm_judge

    prompts: list[PromptDTO]
    tools: list[ToolDTO] = field(default_factory=list)

    detector_substrings: list[str] = field(default_factory=list)
    detector_is_negation: bool = False

    judge_system_prompt: Optional[str] = None
    judge_true_description: Optional[str] = None
    attacker_system_prompt: Optional[str] = None

    max_turns: int = 1

    def has_tools(self) -> bool:
        return len(self.tools) > 0

    def get_openai_tools(self) -> list[dict[str, Any]]:
        return [t.to_openai_tool() for t in self.tools]


# ---------------------------------------------------------------------------
# DTO: результаты
# ---------------------------------------------------------------------------


@dataclass
class AttackResultDTO:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    prompt_id: Optional[str] = None
    turn_number: int = 1
    original_prompt: str = ""
    response: str = ""
    response_tool_calls: Optional[list[dict[str, Any]]] = None
    detector_verdict: str = "miss"
    detector_score: float = 0.0
    judge_reasoning: Optional[str] = None
    is_hit: bool = False
    conversation_history: Optional[list[dict[str, str]]] = None


@dataclass
class AttackRunDTO:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    attack_id: str = ""
    attack_name: str = ""
    category: str = ""
    total_prompts: int = 0
    successful_hits: int = 0
    success_rate: float = 0.0
    status: str = "pending"
    results: list[AttackResultDTO] = field(default_factory=list)
    duration_seconds: float = 0.0


# ---------------------------------------------------------------------------
# Конвертер PyRIT AttackResult -> наш DTO
# ---------------------------------------------------------------------------


def _pyrit_result_to_dto(
    pyrit_result: PyRITAttackResult,
    prompt_id: Optional[str] = None,
) -> AttackResultDTO:
    is_hit = pyrit_result.outcome == AttackOutcome.SUCCESS

    response_text = ""
    if pyrit_result.last_response:
        response_text = pyrit_result.last_response.converted_value or ""

    tool_calls: Optional[list[dict[str, Any]]] = None
    if response_text.strip().startswith("{") and '"function"' in response_text:
        try:
            parsed = json.loads(response_text)
            if "function" in parsed:
                tool_calls = [parsed]
        except (json.JSONDecodeError, TypeError):
            pass

    score_val = 0.0
    reasoning = None
    if pyrit_result.last_score:
        score_val = 1.0 if is_hit else 0.0
        reasoning = pyrit_result.last_score.score_rationale

    conversation: list[dict[str, str]] = []
    try:
        memory = CentralMemory.get_memory_instance()
        messages = memory.get_conversation(conversation_id=pyrit_result.conversation_id)
        for msg in messages:
            role = msg.api_role.value if hasattr(msg.api_role, "value") else str(msg.api_role)
            conversation.append({"role": role, "content": msg.get_value()})
    except Exception as e:
        logger.debug("Could not retrieve conversation: %s", e)

    return AttackResultDTO(
        prompt_id=prompt_id,
        turn_number=pyrit_result.executed_turns,
        original_prompt=pyrit_result.objective,
        response=response_text,
        response_tool_calls=tool_calls,
        detector_verdict="hit" if is_hit else "miss",
        detector_score=score_val,
        judge_reasoning=reasoning,
        is_hit=is_hit,
        conversation_history=conversation if conversation else None,
    )


# ---------------------------------------------------------------------------
# AttackRunner
# ---------------------------------------------------------------------------


class AttackRunner:

    def __init__(
        self,
        target: OpenAIChatTarget,
        target_config: TargetConfig,
        attacker: Optional[OpenAIChatTarget] = None,
        judge: Optional[OpenAIChatTarget] = None,
    ) -> None:
        self.target = target
        self.target_config = target_config
        self.attacker = attacker
        self.judge = judge

    def run(self, pipeline: AttackPipeline) -> AttackRunDTO:
        return asyncio.run(self.run_async(pipeline))

    async def run_async(self, pipeline: AttackPipeline) -> AttackRunDTO:
        run = AttackRunDTO(
            attack_id=pipeline.attack_id,
            attack_name=pipeline.name,
            category=pipeline.category,
        )
        run.status = "running"
        t0 = time.time()

        try:
            scorer = self._build_scorer(pipeline)
            scoring_config = AttackScoringConfig(objective_scorer=scorer)
            effective_target = self._resolve_target(pipeline)

            if pipeline.orchestrator_type == "red_teaming":
                results = await self._run_red_teaming(pipeline, scoring_config, effective_target)
            else:
                results = await self._run_prompt_sending(pipeline, scoring_config, effective_target)

            run.results = results
            run.total_prompts = len(results)
            run.successful_hits = sum(1 for r in results if r.is_hit)
            run.success_rate = run.successful_hits / run.total_prompts if run.total_prompts > 0 else 0.0
            run.status = "completed"

        except Exception as e:
            logger.error("Attack %s failed: %s", pipeline.name, e, exc_info=True)
            run.status = "failed"

        run.duration_seconds = time.time() - t0
        return run

    def _resolve_target(self, pipeline: AttackPipeline) -> OpenAIChatTarget:
        if pipeline.has_tools():
            logger.info("Attack %s has %d tools, using ToolEnabledTarget", pipeline.name, len(pipeline.tools))
            return create_tool_target(config=self.target_config, tools=pipeline.get_openai_tools())
        return self.target

    async def _run_prompt_sending(
        self, pipeline: AttackPipeline, scoring_config: AttackScoringConfig, target: OpenAIChatTarget,
    ) -> list[AttackResultDTO]:
        results: list[AttackResultDTO] = []
        attack = PromptSendingAttack(objective_target=target, attack_scoring_config=scoring_config)

        for prompt_dto in pipeline.prompts:
            try:
                pyrit_result = await attack.execute_async(objective=prompt_dto.content)
                dto = _pyrit_result_to_dto(pyrit_result, prompt_id=prompt_dto.id)
                results.append(dto)
                logger.info("Prompt %s: %s", prompt_dto.id, dto.detector_verdict)
            except Exception as e:
                logger.warning("Prompt %s failed: %s", prompt_dto.id, e)
                results.append(AttackResultDTO(
                    prompt_id=prompt_dto.id, original_prompt=prompt_dto.content,
                    detector_verdict="error", response=f"ERROR: {e}",
                ))
        return results

    async def _run_red_teaming(
        self, pipeline: AttackPipeline, scoring_config: AttackScoringConfig, target: OpenAIChatTarget,
    ) -> list[AttackResultDTO]:
        if not self.attacker:
            logger.warning("Red teaming requires attacker LLM, falling back to prompt_sending")
            return await self._run_prompt_sending(pipeline, scoring_config, target)

        results: list[AttackResultDTO] = []
        adversarial_config = AttackAdversarialConfig(target=self.attacker)

        system_prompt_path = None
        if pipeline.attacker_system_prompt:
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8")
            yaml.dump({"content": pipeline.attacker_system_prompt}, tmp, allow_unicode=True)
            tmp.close()
            system_prompt_path = tmp.name
            adversarial_config = AttackAdversarialConfig(target=self.attacker, system_prompt_path=system_prompt_path)

        attack = RedTeamingAttack(
            objective_target=target,
            attack_adversarial_config=adversarial_config,
            attack_scoring_config=scoring_config,
            max_turns=pipeline.max_turns,
        )

        for prompt_dto in pipeline.prompts:
            try:
                pyrit_result = await attack.execute_async(objective=prompt_dto.content)
                dto = _pyrit_result_to_dto(pyrit_result, prompt_id=prompt_dto.id)
                results.append(dto)
                logger.info("Red team %s: %s after %d turns", prompt_dto.id, dto.detector_verdict, dto.turn_number)
            except Exception as e:
                logger.warning("Red team %s failed: %s", prompt_dto.id, e)
                results.append(AttackResultDTO(
                    prompt_id=prompt_dto.id, original_prompt=prompt_dto.content,
                    detector_verdict="error", response=f"ERROR: {e}",
                ))

        if system_prompt_path:
            try:
                os.unlink(system_prompt_path)
            except OSError:
                pass

        return results

    def _build_scorer(self, pipeline: AttackPipeline) -> TrueFalseScorer:
        if pipeline.scorer_type == "llm_judge":
            if not self.judge:
                raise ValueError(f"Attack {pipeline.name} requires LLM judge but no judge target configured")
            return create_llm_judge_scorer(
                judge_target=self.judge,
                true_description=pipeline.judge_true_description or "The attack objective was achieved",
            )
        else:
            if not pipeline.detector_substrings:
                raise ValueError(f"Attack {pipeline.name} uses substring scorer but has no substrings")
            return create_substring_scorer(
                substrings=pipeline.detector_substrings,
                is_negation=pipeline.detector_is_negation,
            )
