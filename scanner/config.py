"""Pydantic configuration models for LLM Fuzzing Scanner."""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class AttackCategory(str, Enum):
    JAILBREAK = "jailbreak"
    PROMPT_INJECTION = "prompt_injection"
    SYSTEM_PROMPT_LEAKAGE = "system_prompt_leakage"
    TOOL_ABUSE = "tool_abuse"


class OrchestratorType(str, Enum):
    PROMPT_SENDING = "prompt_sending"
    RED_TEAMING = "red_teaming"


class ScorerType(str, Enum):
    SUBSTRING = "substring"
    LLM_JUDGE = "llm_judge"


# ---------------------------------------------------------------------------
# Target / Model configuration
# ---------------------------------------------------------------------------


class TargetConfig(BaseModel):
    url: str
    model: str
    api_key: str = "dummy"


# ---------------------------------------------------------------------------
# Simple Mode
# ---------------------------------------------------------------------------


class SimpleConfig(BaseModel):
    target: TargetConfig
    attacks: list[str]  # attack names from DB
    attacker: Optional[TargetConfig] = None
    judge: Optional[TargetConfig] = None
    output_dir: str = "./reports"
    max_prompts_per_attack: int = 100


# ---------------------------------------------------------------------------
# Advanced Mode (YAML)
# ---------------------------------------------------------------------------


class PromptSelector(BaseModel):
    category: Optional[AttackCategory] = None
    source: Optional[str] = None
    tags: Optional[list[str]] = None
    limit: int = 100


class ScorerConfig(BaseModel):
    type: ScorerType
    substrings_group: Optional[str] = None
    is_negation: bool = False
    judge_instruction: Optional[str] = None


class AttackConfig(BaseModel):
    name: str
    category: AttackCategory
    orchestrator: OrchestratorType
    max_turns: int = 1
    attacker_instruction: Optional[str] = None
    prompts: Optional[PromptSelector] = None
    converters: list[str] = []
    scorer: Optional[ScorerConfig] = None


class ScanConfig(BaseModel):
    target: TargetConfig
    attacker: Optional[TargetConfig] = None
    judge: Optional[TargetConfig] = None
    output_dir: str = "./reports"


class AdvancedConfig(BaseModel):
    scan: ScanConfig
    attacks: list[AttackConfig]
