"""
Фабрика PyRIT targets с отключённой проверкой SSL.

- create_target()      -- обычный OpenAIChatTarget (target, attacker, judge)
- create_tool_target()  -- ToolEnabledTarget (tool_abuse, tools в каждом запросе)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

import httpx
from pyrit.prompt_target import OpenAIChatTarget

from tool_target import ToolEnabledTarget


@dataclass
class TargetConfig:
    url: str
    model: str
    api_key: str = "dummy"


def _make_insecure_kwargs(config: TargetConfig, temperature: Optional[float] = None) -> dict[str, Any]:
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
    return OpenAIChatTarget(**_make_insecure_kwargs(config, temperature))


def create_tool_target(
    config: TargetConfig,
    tools: list[dict[str, Any]],
    temperature: Optional[float] = None,
) -> ToolEnabledTarget:
    kwargs = _make_insecure_kwargs(config, temperature)
    return ToolEnabledTarget(tools=tools, **kwargs)
