"""Model provider factory — creates SDK clients with configured auth.

This is the single point where SDK clients are constructed. Everything
above this layer (PydanticAI, agents, passes) is auth-agnostic.

Separated from providers.py (model routing) so auth mode can be
swapped via config without touching model construction logic.

Providers are cached per credential — lru_cache keys on the actual
secret so a changed key naturally creates a fresh client. Tests can
call .cache_clear() on any factory to reset state.
"""
from __future__ import annotations

from functools import lru_cache

import structlog

from security_review.errors import ConfigurationError

logger = structlog.get_logger()


@lru_cache(maxsize=1)
def get_anthropic_provider(api_key: str):
    """Create a PydanticAI AnthropicProvider with API key auth.

    Cached by api_key — a changed key creates a fresh client.
    """
    from anthropic import AsyncAnthropic
    from pydantic_ai.providers.anthropic import AnthropicProvider

    client = AsyncAnthropic(api_key=api_key)
    logger.info("provider.anthropic_ready", auth_mode="api_key")
    return AnthropicProvider(anthropic_client=client)


@lru_cache(maxsize=1)
def get_openai_provider(api_key: str):
    """Create a PydanticAI OpenAIProvider with API key auth.

    Cached by api_key — a changed key creates a fresh client.
    """
    from openai import AsyncOpenAI
    from pydantic_ai.providers.openai import OpenAIProvider

    client = AsyncOpenAI(api_key=api_key)
    logger.info("provider.openai_ready", auth_mode="api_key")
    return OpenAIProvider(openai_client=client)


@lru_cache(maxsize=1)
def get_codex_oauth_provider(token: str):
    """Create a PydanticAI OpenAIProvider with Codex OAuth (subscription billing).

    Uses ChatGPT subscription (Plus/Pro) instead of per-token API billing.
    First run opens browser for PKCE OAuth; tokens auto-refresh after that.
    Tokens cached in ~/.codex-auth/auth.json.

    Cached by token — a changed token creates a fresh client.

    Requires: pip install codex-auth

    Note: The Codex Responses API returns null for usage tokens.
    We patch the client to default these to 0 so PydanticAI validation passes.
    """
    from pydantic_ai.providers.openai import OpenAIProvider

    try:
        from codex_auth import AsyncCodexClient
    except ImportError:
        raise ConfigurationError(
            "codex-auth is required for codex: provider. "
            "Install with: pip install codex-auth",
            code="SYS_DEPENDENCY_MISSING",
        )

    # AsyncCodexClient IS AsyncOpenAI — intercepts requests, rewrites to
    # Codex Responses API, injects OAuth bearer token, auto-refreshes.
    client = AsyncCodexClient(token=token) if token else AsyncCodexClient()

    # Patch: codex-auth has two incompatibilities with PydanticAI:
    # 1. Responses API returns null usage tokens (PydanticAI validates as int)
    # 2. Responses API rejects null content in messages (PydanticAI sends these)
    # We patch chat.completions.create to fix both before/after the request.
    _original_create = client.chat.completions.create

    async def _patched_create(*args, **kwargs):
        # Fix null content: filter messages with content=None or set to ""
        if "messages" in kwargs:
            for msg in kwargs["messages"]:
                if isinstance(msg, dict) and msg.get("content") is None:
                    msg["content"] = ""

        response = await _original_create(*args, **kwargs)

        # Fix null usage tokens
        if hasattr(response, "usage") and response.usage:
            if response.usage.prompt_tokens is None:
                response.usage.prompt_tokens = 0
            if response.usage.completion_tokens is None:
                response.usage.completion_tokens = 0
        return response

    client.chat.completions.create = _patched_create

    logger.info("provider.codex_oauth_ready", auth_mode="codex_oauth")
    return OpenAIProvider(openai_client=client)


def resolve_api_key(provider: str) -> str:
    """Resolve the API key for a provider from environment or config/.env.

    This is the single point where secrets are resolved. Factory functions
    above receive the key as an explicit parameter — they never read env.
    """
    import os

    from security_review.config import get_settings

    if provider == "anthropic":
        key = os.environ.get("ANTHROPIC_API_KEY") or get_settings().anthropic_api_key
        if not key:
            raise ConfigurationError(
                "ANTHROPIC_API_KEY not set. Set it in environment or config/.env.",
                code="SYS_SECRET_MISSING",
            )
        return key

    if provider == "openai":
        key = os.environ.get("OPENAI_API_KEY") or get_settings().openai_api_key
        if not key:
            raise ConfigurationError(
                "OPENAI_API_KEY not set. Set it in environment or config/.env.",
                code="SYS_SECRET_MISSING",
            )
        return key

    if provider == "codex":
        # Codex OAuth token is optional — empty string triggers browser PKCE flow
        return os.environ.get("CODEX_AUTH_TOKEN") or ""

    raise ConfigurationError(
        f"No API key resolution for provider '{provider}'",
        code="SYS_SECRET_MISSING",
    )
