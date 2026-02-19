"""
ToolEnabledTarget -- wraps OpenAIChatTarget to inject OpenAI function calling tools
into every request.

When an attack has tools, this target is used instead of the plain OpenAIChatTarget.
It overrides _construct_request_body to add the `tools` parameter to the API call.

PyRIT already handles tool_calls in responses:
- finish_reason="tool_calls" is treated as valid
- tool_calls are serialized as JSON into response_text_pieces
- scorers can then detect substrings in the serialized tool_call arguments
"""

from __future__ import annotations

import json
from collections.abc import MutableSequence
from typing import Any, Optional

from pyrit.prompt_target import OpenAIChatTarget
from pyrit.models import Message

from scanner.config import TargetConfig


class ToolEnabledTarget(OpenAIChatTarget):
    """
    OpenAIChatTarget that injects `tools` into every Chat Completions request.

    Usage:
        target = ToolEnabledTarget(
            endpoint="http://...",
            model_name="...",
            api_key="...",
            tools=[{"type": "function", "function": {...}}],
            httpx_client_kwargs={"http_client": httpx.AsyncClient(verify=False)},
        )

    The `tools` parameter is added to the request body alongside messages, model, etc.
    When the model returns tool_calls, PyRIT's base class serializes them as JSON
    response pieces, which can then be scored by SubStringScorer.
    """

    def __init__(
        self,
        *,
        tools: list[dict[str, Any]],
        **kwargs: Any,
    ) -> None:
        """
        Args:
            tools: List of OpenAI function calling tool definitions
                   (each with "type": "function", "function": {...}).
            **kwargs: All other arguments passed to OpenAIChatTarget.
        """
        super().__init__(**kwargs)
        self._tools = tools

    async def _construct_request_body(
        self, *, conversation: MutableSequence[Message], json_config: Any
    ) -> dict[str, Any]:
        """Override to inject tools into the API request body."""
        body = await super()._construct_request_body(
            conversation=conversation, json_config=json_config,
        )
        if self._tools:
            body["tools"] = self._tools
        return body
