"""LLM provider routing for PydanticAI agents.

Builds a PydanticAI Model from a prefixed string like 'copilot:claude-sonnet'.
Model names are resolved through config/models.yaml:
  1. Short aliases (claude-sonnet -> claude-sonnet-4.6)
  2. Provider-specific overrides (anthropic: claude-sonnet-4.6 -> claude-sonnet-4-6)

Supported providers:
    copilot:claude-sonnet-4.6       — GitHub Copilot SDK (OAuth, $0 via subscription)
    copilot:claude-opus-4.6         — GitHub Copilot SDK
    copilot:gpt-5.4                 — GitHub Copilot SDK
    claude:claude-sonnet-4-5    — Claude Max/Pro subscription via Agent SDK ($0)
    claude:claude-opus-4-7      — Claude Max/Pro subscription via Agent SDK ($0)
    anthropic:claude-sonnet-4-6     — Anthropic API key (per-token)
    openai:gpt-5.5                  — OpenAI API key (per-token)
    codex:gpt-5.4                   — Codex app-server SDK (ChatGPT Plus/Pro subscription, $0)
"""
from __future__ import annotations

from functools import lru_cache
from typing import Any

import structlog
import yaml

from security_review import MODULE_ROOT
from security_review.errors import ConfigurationError

logger = structlog.get_logger()


@lru_cache(maxsize=1)
def _load_model_registry() -> dict:
    """Load model aliases and provider overrides from config/models.yaml."""
    models_path = MODULE_ROOT / "config" / "models.yaml"
    if not models_path.exists():
        raise ConfigurationError(
            f"Model registry not found: {models_path}",
            code="SYS_CONFIG_INVALID",
        )

    with open(models_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ConfigurationError(
            f"Model registry is not a YAML mapping: {models_path}",
            code="SYS_CONFIG_INVALID",
        )
    return data


def resolve_model_name(provider: str, model_name: str) -> str:
    """Resolve a model name through aliases and provider overrides.

    1. If model_name is a short alias (e.g. 'claude-sonnet'), expand it
    2. If the provider has an override for the resolved name, apply it
    """
    registry = _load_model_registry()

    # Step 1: Alias expansion
    aliases = registry.get("aliases", {})
    resolved = aliases.get(model_name, model_name)

    # Step 2: Provider-specific override
    provider_overrides = registry.get("providers", {}).get(provider, {})
    final = provider_overrides.get(resolved, resolved)

    if final != model_name:
        logger.debug(
            "model.resolved",
            input=f"{provider}:{model_name}",
            resolved=f"{provider}:{final}",
        )

    return final


# Per-provider shared limiters — keyed on (provider, max_concurrent) so that
# different concurrency settings create distinct limiters. Shared across all passes
# within a pipeline run so triage + holistic + config_review respect a single gate.
_provider_limiters: dict[tuple[str, int], Any] = {}


def _get_limiter(provider: str, max_concurrent: int):
    """Get or create a shared ConcurrencyLimiter for a provider+concurrency pair."""
    key = (provider, max_concurrent)
    if key not in _provider_limiters:
        from pydantic_ai.concurrency import ConcurrencyLimiter
        _provider_limiters[key] = ConcurrencyLimiter(
            max_running=max_concurrent, name=f"provider:{provider}",
        )
        logger.debug(
            "provider.limiter_created",
            provider=provider,
            max_concurrent=max_concurrent,
        )
    return _provider_limiters[key]


def reset_provider_limiters() -> None:
    """Test hook: clear the shared per-provider limiters (mirrors the
    .cache_clear() convention in model_providers.py)."""
    _provider_limiters.clear()


def build_model(model_string: str, *, llm_config: "LLMConfig"):
    """Build a PydanticAI Model from a prefixed string.

    Applies ConcurrencyLimitedModel wrapper using provider-specific settings
    from llm_config.providers.{provider_name}. Limiters are shared per provider
    so all passes respect a single rate-limit gate.
    """
    from pydantic_ai.models.concurrency import ConcurrencyLimitedModel

    from security_review.config_schema import LLMConfig

    provider, _, model_name = model_string.partition(":")
    if not model_name:
        raise ConfigurationError(
            f"Model string must be 'provider:model', got '{model_string}'",
            code="SYS_CONFIGURATION_ERROR",
        )

    # Resolve aliases and provider-specific names
    model_name = resolve_model_name(provider, model_name)

    # Get provider-specific config (concurrency, timeouts)
    cfg = llm_config
    provider_cfg = cfg.provider_config(provider)
    limiter = _get_limiter(provider, provider_cfg.max_concurrent)

    if provider == "openai":
        from pydantic_ai.models.openai import OpenAIChatModel
        from security_review.model_providers import get_openai_provider, resolve_api_key
        inner = OpenAIChatModel(model_name, provider=get_openai_provider(resolve_api_key("openai")))

    elif provider == "foundry":
        from pydantic_ai.models.openai import OpenAIChatModel
        from security_review.model_providers import get_foundry_provider
        if not (cfg.foundry_base_url and cfg.foundry_api_version and cfg.foundry_token_scope):
            raise ConfigurationError(
                "foundry: models require llm.foundry_base_url, llm.foundry_api_version, "
                "and llm.foundry_token_scope in config/settings/security_review.yaml.",
                code="SYS_CONFIG_INVALID",
            )
        # model_name is the Azure *deployment* name, not the catalogue model ID.
        # They match on this resource, which config/models.yaml keeps true via
        # its foundry overrides — Azure routes on the deployment.
        inner = OpenAIChatModel(
            model_name,
            provider=get_foundry_provider(
                cfg.foundry_base_url, cfg.foundry_api_version, cfg.foundry_token_scope,
            ),
        )

    elif provider == "anthropic":
        from pydantic_ai.models.anthropic import AnthropicModel
        from security_review.model_providers import get_anthropic_provider, resolve_api_key
        inner = AnthropicModel(model_name, provider=get_anthropic_provider(resolve_api_key("anthropic")))

    elif provider == "copilot":
        from security_review.copilot_model import CopilotModel
        inner = CopilotModel(
            model_id=model_name,
            session_timeout=provider_cfg.session_timeout,
            backoff_seconds=provider_cfg.backoff_seconds,
        )

    elif provider == "claude":
        from security_review.claude_model import ClaudeModel
        inner = ClaudeModel(model_id=model_name)

    elif provider == "codex":
        from security_review.codex_model import CodexModel
        inner = CodexModel(model_id=model_name)

    else:
        raise ConfigurationError(
            f"Unsupported provider '{provider}'",
            code="SYS_CONFIGURATION_ERROR",
        )

    from security_review.retry_model import RetryingModel

    # RetryingModel is the OUTERMOST wrapper so each retry re-acquires the
    # concurrency slot cleanly (plan 020 Phase 3). It activates
    # backoff_seconds uniformly for all five providers.
    model = ConcurrencyLimitedModel(inner, limiter=limiter)
    model = RetryingModel(model, backoff_seconds=provider_cfg.backoff_seconds, provider=provider)
    logger.debug(
        "provider.model_built",
        provider=provider,
        model=model_name,
        max_concurrent=provider_cfg.max_concurrent,
        session_timeout=provider_cfg.session_timeout,
        backoff_seconds=provider_cfg.backoff_seconds,
    )
    return model
