"""
AttackPipeline -- fully resolved attack description ready for execution.

Built from an Attack (DB entity) with all relationships loaded.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class PromptDTO:
    id: str
    content: str


@dataclass
class ToolDTO:
    """OpenAI function calling tool definition."""
    name: str
    description: str
    parameters_schema: dict[str, Any]

    def to_openai_tool(self) -> dict[str, Any]:
        """Convert to OpenAI tools format."""
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
    """Fully resolved attack configuration ready for execution."""

    # Identity
    attack_id: str
    name: str
    category: str
    orchestrator_type: str  # prompt_sending | red_teaming
    scorer_type: str        # substring | llm_judge

    # Prompts
    prompts: list[PromptDTO]

    # Tools (sent with every request if non-empty)
    tools: list[ToolDTO] = field(default_factory=list)

    # Substring detector config
    detector_substrings: list[str] = field(default_factory=list)
    detector_is_negation: bool = False

    # LLM judge config
    judge_system_prompt: Optional[str] = None
    judge_true_description: Optional[str] = None

    # Attacker LLM config (for red_teaming)
    attacker_system_prompt: Optional[str] = None

    # Converter chain + execution params
    converter_names: list[str] = field(default_factory=list)
    max_turns: int = 1

    def has_tools(self) -> bool:
        return len(self.tools) > 0

    def get_openai_tools(self) -> list[dict[str, Any]]:
        return [t.to_openai_tool() for t in self.tools]
