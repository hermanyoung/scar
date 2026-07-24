"""Tests for model-name resolution and build_model errors (Plan 019 WP-G)."""
from __future__ import annotations

import pytest

from security_review.config import load_config
from security_review.errors import ConfigurationError
from security_review.providers import (
    _get_limiter,
    _provider_limiters,
    build_model,
    reset_provider_limiters,
    resolve_model_name,
)


def test_resolve_alias_copilot():
    assert resolve_model_name("copilot", "claude-opus") == "claude-opus-4.6"


def test_resolve_alias_anthropic_provider_override():
    assert resolve_model_name("anthropic", "claude-opus") == "claude-opus-4-6"


def test_resolve_canonical_passes_through():
    assert resolve_model_name("copilot", "claude-opus-4.6") == "claude-opus-4.6"


def test_build_model_unknown_provider_raises():
    cfg = load_config(None)
    with pytest.raises(ConfigurationError) as exc_info:
        build_model("nonsense:x", llm_config=cfg.llm)
    # Unknown providers fail fast at the provider-config lookup with the
    # provider named in the message.
    assert "nonsense" in str(exc_info.value)


def test_build_model_missing_model_raises():
    cfg = load_config(None)
    with pytest.raises(ConfigurationError) as exc_info:
        build_model("copilot", llm_config=cfg.llm)
    assert "provider:model" in str(exc_info.value)


def test_reset_provider_limiters_empties_dict():
    _get_limiter("test-provider", 3)
    assert _provider_limiters
    reset_provider_limiters()
    assert _provider_limiters == {}
