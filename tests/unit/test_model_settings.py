"""Tests for provider-specific ModelSettings, especially reasoning depth.

Reasoning effort is the OpenAI-family counterpart of Anthropic extended
thinking. Left unset, a foundry: deployment answers from the prompt alone and
spends zero reasoning tokens, which cost two CWEs on the golden target.
"""
from __future__ import annotations

import pytest

from security_review.config import load_config
from security_review.config_schema import LLMConfig
from security_review.model_settings import build_model_settings


@pytest.fixture
def llm() -> LLMConfig:
    return load_config(None).llm


@pytest.mark.parametrize("model_string", ["foundry:gpt-5.4", "openai:gpt"])
def test_reasoning_effort_applied_to_openai_family(llm: LLMConfig, model_string: str):
    llm = llm.model_copy(update={"reasoning_effort": "high"})
    settings = build_model_settings(model_string, llm)
    assert settings["openai_reasoning_effort"] == "high"


def test_reasoning_effort_suppresses_temperature(llm: LLMConfig):
    """The SDK rejects sampling parameters once reasoning is enabled."""
    llm = llm.model_copy(update={"reasoning_effort": "high", "temperature": 0.2})
    settings = build_model_settings("foundry:gpt-5.4", llm)
    assert "temperature" not in settings


def test_unset_reasoning_effort_falls_back_to_temperature(llm: LLMConfig):
    llm = llm.model_copy(update={"reasoning_effort": None, "temperature": 0.2})
    settings = build_model_settings("foundry:gpt-5.4", llm)
    assert "openai_reasoning_effort" not in settings
    assert settings["temperature"] == 0.2


@pytest.mark.parametrize("model_string", ["anthropic:claude-opus", "copilot:claude-opus"])
def test_reasoning_effort_not_sent_to_other_providers(llm: LLMConfig, model_string: str):
    """Only OpenAI-family models take this parameter; the rest would reject it."""
    llm = llm.model_copy(update={"reasoning_effort": "high"})
    settings = build_model_settings(model_string, llm)
    assert "openai_reasoning_effort" not in settings


def test_anthropic_thinking_still_applies_alongside(llm: LLMConfig):
    """Setting the OpenAI knob must not disturb the Anthropic one."""
    llm = llm.model_copy(update={"reasoning_effort": "high", "thinking_budget": 10_000})
    settings = build_model_settings("anthropic:claude-opus", llm)
    assert settings["anthropic_thinking"]["budget_tokens"] == 10_000


def test_invalid_reasoning_effort_rejected_at_config_load(llm: LLMConfig):
    """Fail loudly on a typo rather than silently sending it to the provider."""
    base = llm.model_dump()

    LLMConfig.model_validate({**base, "reasoning_effort": "high"})

    with pytest.raises(ValueError, match="reasoning_effort"):
        LLMConfig.model_validate({**base, "reasoning_effort": "very-high"})
