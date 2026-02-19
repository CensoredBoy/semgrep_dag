"""
Concrete catalog implementations for all 5 component types + Attack.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from scanner.catalogs.base import BaseCatalog
from scanner.data.models import (
    Attack,
    AttackerInstruction,
    DetectorSubstring,
    JudgeInstruction,
    Prompt,
    Tool,
)


class PromptCatalog(BaseCatalog[Prompt]):
    model_class = Prompt

    def _apply_filters(self, stmt: Any, **filters: Any) -> Any:
        if "source" in filters:
            stmt = stmt.where(Prompt.source == filters["source"])
        if "language" in filters:
            stmt = stmt.where(Prompt.language == filters["language"])
        if "category" in filters:
            # tags stored as JSON array, do LIKE search
            stmt = stmt.where(Prompt.tags.contains(filters["category"]))
        return stmt

    def add_prompt(
        self,
        content: str,
        source: str = "custom",
        language: str = "en",
        tags: Optional[list[str]] = None,
    ) -> Prompt:
        prompt = Prompt(
            content=content,
            source=source,
            language=language,
            tags=json.dumps(tags or []),
        )
        return self.add(prompt)


class AttackerCatalog(BaseCatalog[AttackerInstruction]):
    model_class = AttackerInstruction

    def add_instruction(
        self,
        name: str,
        system_prompt: str,
        description: str = "",
    ) -> AttackerInstruction:
        entity = AttackerInstruction(
            name=name,
            system_prompt=system_prompt,
            description=description,
        )
        return self.add(entity)


class DetectorCatalog(BaseCatalog[DetectorSubstring]):
    model_class = DetectorSubstring

    def _apply_filters(self, stmt: Any, **filters: Any) -> Any:
        if "source" in filters:
            stmt = stmt.where(DetectorSubstring.source == filters["source"])
        return stmt

    def add_substring(
        self,
        substring: str,
        source: str = "custom",
        is_negation: bool = False,
        description: str = "",
    ) -> DetectorSubstring:
        entity = DetectorSubstring(
            substring=substring,
            source=source,
            is_negation=is_negation,
            description=description,
        )
        return self.add(entity)


class JudgeCatalog(BaseCatalog[JudgeInstruction]):
    model_class = JudgeInstruction

    def add_instruction(
        self,
        name: str,
        system_prompt: str,
        true_description: str,
        description: str = "",
    ) -> JudgeInstruction:
        entity = JudgeInstruction(
            name=name,
            system_prompt=system_prompt,
            true_description=true_description,
            description=description,
        )
        return self.add(entity)


class ToolCatalog(BaseCatalog[Tool]):
    model_class = Tool

    def add_tool(
        self,
        name: str,
        description: str = "",
        parameters_schema: Optional[dict[str, Any]] = None,
    ) -> Tool:
        entity = Tool(
            name=name,
            description=description,
            parameters_schema=json.dumps(parameters_schema or {}),
        )
        return self.add(entity)


class AttackCatalog(BaseCatalog[Attack]):
    model_class = Attack

    def _apply_filters(self, stmt: Any, **filters: Any) -> Any:
        if "category" in filters:
            stmt = stmt.where(Attack.category == filters["category"])
        return stmt

    def get_by_names(self, names: list[str]) -> list[Attack]:
        """Get multiple attacks by name."""
        stmt = select(Attack).where(Attack.name.in_(names))
        return list(self.session.execute(stmt).scalars().all())
