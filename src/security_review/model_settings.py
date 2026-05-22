"""Build provider-specific ModelSettings for PydanticAI agent.run() calls.

Anthropic supports:
  - Prompt caching: system prompts cached across calls (90% input token savings)
  - Extended thinking: deeper reasoning for complex CWE checks

Copilot/OpenAI: no provider-specific settings (returns None).

Usage:
    settings = build_model_settings("anthropic:claude-sonnet-4-6", state.config.llm)
    result = await agent.run(prompt, model=model, model_settings=settings)
"""
from __future__ import annotations

import structlog
from pydantic_ai.settings import ModelSettings

from security_review.config_schema import LLMConfig

logger = structlog.get_logger()


def build_model_settings(model_string: str, llm_config: LLMConfig) -> ModelSettings:
    """Build provider-specific ModelSettings from config.

    Returns AnthropicModelSettings for anthropic: provider (cache + thinking + temperature).
    Returns ModelSettings with temperature for other providers when temperature is configured.
    Returns empty ModelSettings when no overrides apply.
    """
    provider = model_string.split(":")[0] if ":" in model_string else ""

    temperature = llm_config.temperature

    if provider == "anthropic":
        from pydantic_ai.models.anthropic import AnthropicModelSettings

        kwargs: dict = {}

        # Prompt caching — reduces cost by ~90% on repeated system prompts.
        cache_ttl = llm_config.cache_ttl
        if cache_ttl:
            kwargs["anthropic_cache_instructions"] = cache_ttl
            kwargs["anthropic_cache_tool_definitions"] = cache_ttl
            kwargs["anthropic_cache"] = True

        # Extended thinking — deeper reasoning for complex security analysis.
        # When thinking is enabled, Anthropic requires temperature=1.0 (do not set it).
        if llm_config.thinking_budget:
            model_name = model_string.split(":", 1)[1] if ":" in model_string else ""
            adaptive_models = ("claude-opus-4", "claude-sonnet-4", "opus-4", "sonnet-4")
            use_adaptive = any(m in model_name for m in adaptive_models)
            if use_adaptive:
                kwargs["anthropic_thinking"] = {"type": "adaptive"}
            else:
                kwargs["anthropic_thinking"] = {
                    "type": "enabled",
                    "budget_tokens": llm_config.thinking_budget,
                }
        elif temperature is not None:
            # Only set temperature when thinking is off (Anthropic requirement).
            kwargs["temperature"] = temperature

        if not kwargs:
            return ModelSettings()

        logger.debug(
            "model_settings.built",
            provider=provider,
            cache_ttl=cache_ttl,
            thinking_budget=llm_config.thinking_budget,
            temperature=temperature,
        )
        return AnthropicModelSettings(**kwargs)

    # Non-anthropic providers: apply temperature if configured.
    if temperature is not None:
        return ModelSettings(temperature=temperature)

    return ModelSettings()
