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


def test_resolve_foundry_alias_targets_a_deployed_model():
    """Foundry addresses deployments, so shared aliases must be remapped."""
    assert resolve_model_name("foundry", "gpt") == "gpt-5.4"
    assert resolve_model_name("foundry", "gpt-mini") == "gpt-5-mini"
    assert resolve_model_name("foundry", "gpt-5-nano") == "gpt-5-nano"


def test_build_model_foundry_uses_azure_and_resolves_deployment():
    cfg = load_config(None)
    model = build_model("foundry:gpt", llm_config=cfg.llm)
    assert model.model_name == "gpt-5.4"
    assert model.system == "azure"


def test_build_model_foundry_without_endpoint_raises():
    cfg = load_config(None)
    llm = cfg.llm.model_copy(update={"foundry_base_url": None})
    with pytest.raises(ConfigurationError) as exc_info:
        build_model("foundry:gpt-5-nano", llm_config=llm)
    assert "foundry_base_url" in str(exc_info.value)


def test_foundry_models_are_priced():
    """A foundry model with no pricing entry aborts the run at first LLM call."""
    from security_review.budget import pricing_entry_exists
    for model in ("foundry:gpt-5.4", "foundry:gpt-5-mini", "foundry:gpt-5-nano"):
        assert pricing_entry_exists(model), f"{model} missing from config/pricing.yaml"


def test_config_rejects_foundry_model_without_endpoint_at_load_time():
    """Catch the misconfiguration before inventory and SAST burn wall-clock time."""
    import copy

    import yaml
    from pydantic import ValidationError

    from security_review import MODULE_ROOT
    from security_review.config_schema import SecurityReviewConfig

    with open(MODULE_ROOT / "config" / "settings" / "security_review.yaml") as f:
        raw = copy.deepcopy(yaml.safe_load(f))

    raw["llm"]["provider_model"] = "foundry:gpt-5.4"
    raw["llm"].pop("foundry_base_url", None)

    with pytest.raises(ValidationError) as exc_info:
        SecurityReviewConfig.model_validate(raw)
    assert "llm.foundry_base_url" in str(exc_info.value)


def test_reset_provider_limiters_empties_dict():
    _get_limiter("test-provider", 3)
    assert _provider_limiters
    reset_provider_limiters()
    assert _provider_limiters == {}
