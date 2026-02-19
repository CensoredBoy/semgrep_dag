"""
ToolEnabledTarget -- кастомный PromptTarget, добавляет tools в каждый API-запрос.

Наследует OpenAIChatTarget, переопределяет _construct_request_body,
чтобы в body появился параметр tools для OpenAI Chat Completions.

PyRIT уже поддерживает tool_calls в ответах:
- finish_reason="tool_calls" считается валидным
- tool_calls сериализуются как JSON в response_text_pieces
- scorer может искать подстроки в сериализованных аргументах tool_calls
"""

from __future__ import annotations

from collections.abc import MutableSequence
from typing import Any

from pyrit.prompt_target import OpenAIChatTarget
from pyrit.models import Message


class ToolEnabledTarget(OpenAIChatTarget):

    def __init__(self, *, tools: list[dict[str, Any]], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._tools = tools

    async def _construct_request_body(
        self, *, conversation: MutableSequence[Message], json_config: Any
    ) -> dict[str, Any]:
        body = await super()._construct_request_body(
            conversation=conversation, json_config=json_config,
        )
        if self._tools:
            body["tools"] = self._tools
        return body
