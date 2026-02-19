"""
Factory for creating PyRIT targets with SSL disabled.

- create_target: standard OpenAIChatTarget (for attacker, judge, plain targets)
- create_tool_target: ToolEnabledTarget that injects tools into every request
"""

from __future__ import annotations

from typing import Any, Optional

import httpx
from pyrit.prompt_target import OpenAIChatTarget

from scanner.config import TargetConfig
from scanner.pyrit_adapter.tool_target import ToolEnabledTarget


def _make_insecure_kwargs(config: TargetConfig, temperature: Optional[float] = None) -> dict[str, Any]:
    """Build common kwargs for PyRIT targets with SSL disabled."""
    insecure_client = httpx.AsyncClient(verify=False)
    kwargs: dict[str, Any] = {
        "endpoint": config.url,
        "model_name": config.model,
        "api_key": config.api_key,
        "httpx_client_kwargs": {"http_client": insecure_client},
    }
    if temperature is not None:
        kwargs["temperature"] = temperature
    return kwargs


def create_target(config: TargetConfig, temperature: Optional[float] = None) -> OpenAIChatTarget:
    """
    Create a PyRIT OpenAIChatTarget with SSL verification disabled.

    Used for: target LLM (without tools), attacker LLM, judge LLM.
    """
    return OpenAIChatTarget(**_make_insecure_kwargs(config, temperature))


def create_tool_target(
    config: TargetConfig,
    tools: list[dict[str, Any]],
    temperature: Optional[float] = None,
) -> ToolEnabledTarget:
    """
    Create a ToolEnabledTarget — OpenAIChatTarget that sends tools with every request.

    Used for: tool_abuse attacks where tools must be passed in the API `tools` parameter.
    The model may respond with tool_calls; PyRIT serializes them as JSON response pieces
    which are then scored by SubStringScorer for detection.

    Args:
        config: Target connection configuration.
        tools: List of OpenAI function calling tool definitions.
        temperature: Optional temperature override.
    """
    kwargs = _make_insecure_kwargs(config, temperature)
    return ToolEnabledTarget(tools=tools, **kwargs)
