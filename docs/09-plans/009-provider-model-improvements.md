# Plan 009: Provider & Model Architecture Improvements

**Source:** Comparative analysis of pi-mono (`@mariozechner/pi-ai`) patterns vs SCAR architecture  
**Created:** 8 May 2026  
**Status:** Partially implemented
**Disposition (2026-07-06):** P1 done; P2 rejected (conflicts with pricing.yaml rule + 018 WP4); P3→019 WP-F; P4/P6 not planned.

---

## Overview

This plan addresses six gaps identified by comparing our PydanticAI-based provider layer with pi-mono's transport-centric architecture. Each priority is an independent unit of work — earlier priorities have no dependency on later ones.

**Current State:**
- 5 providers dispatched by prefix string in `providers.py` (`openai:`, `anthropic:`, `copilot:`, `claude:`, `codex:`)
- Capabilities detected externally via `model_capabilities.py` with `AttributeError` fallback
- `output_retries` config field exists but is unused (agents hardcode `retries=1`)
- No context overflow detection — batch too large results in opaque SDK errors
- All SDK imports happen eagerly at module-level within each provider branch
- Adding a new OpenAI-compatible provider (e.g. Azure, Groq) requires a new code path

**Target State:**
- Self-describing model objects with inline capabilities, context windows, and cost metadata
- `output_retries` wired into all agent calls from config
- Automatic overflow detection with batch-splitting recovery
- Consistent retry layer with delay caps across all providers
- Lazy SDK loading — unused providers don't crash the process
- Transport-protocol abstraction separating wire format from brand identity

---

## Priority 1: Wire `output_retries` into Agent Calls

**Goal:** Use the existing `llm.output_retries` config value instead of hardcoded `retries=1`.

**Problem:** `LLMConfig.output_retries` (default: 3) is defined in `config_schema.py` and set in `security_review.yaml`, but every agent definition ignores it and uses `retries=1`.

**Files to modify:**

| File | Change |
|------|--------|
| `src/security_review/agents/triage/agent.py` | Remove `retries=1` from `Agent()` constructor |
| `src/security_review/agents/holistic/agent.py` | Remove `retries=1` from `Agent()` constructor |
| `src/security_review/agents/config_review/agent.py` | Remove `retries=1` from `Agent()` constructor |
| `src/security_review/passes/triage.py` | Pass `retries=llm.output_retries` to `agent.run()` |
| `src/security_review/passes/holistic.py` | Pass `retries=llm.output_retries` to `agent.run()` |
| `src/security_review/passes/config_review.py` | Pass `retries=llm.output_retries` to `agent.run()` |

**Implementation steps:**

1. Remove `retries=1` from all three `Agent()` definitions — PydanticAI defaults to `retries=1` when not specified at agent level, so this is a no-op initially.
2. In each pass (`run_triage`, `run_holistic`, `run_config_review`), pass the config value to the `agent.run()` call:
   ```python
   result = await triage_agent.run(
       prompt,
       model=model,
       model_settings=model_settings,
       usage_limits=UsageLimits(...),
       retries=state.config.llm.output_retries,
   )
   ```
3. Verify PydanticAI's `agent.run(retries=N)` overrides the agent-level default (it does per PydanticAI docs).

**Acceptance:** Setting `output_retries: 1` in YAML results in single-attempt calls; setting `output_retries: 3` retries validation failures up to 3 times. Verify via unit test with `TestModel`.

---

## Priority 2: Self-Describing Model Capabilities Object

**Goal:** Each model carries its own capabilities, context window, cost, and feature flags — eliminating external checks and `config/pricing.yaml`.

**Problem:** Today `supports_native_json()` inspects `model.profile` via `AttributeError` fallback. Context windows, pricing, and reasoning support are either undeclared or in separate files. Adding a new capability check means another function with another `try/except`.

**New file:** `src/security_review/model_registry.py`

**Schema:**

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class ModelCapabilities:
    """Self-describing model metadata — replaces external capability checks."""
    
    model_id: str                    # Canonical ID (e.g. "claude-sonnet-4-6")
    provider: str                    # Transport provider (e.g. "anthropic")
    context_window: int              # Max input tokens
    max_output_tokens: int           # Max output tokens
    supports_json_schema: bool       # Native structured output
    supports_reasoning: bool         # Extended thinking / chain-of-thought
    supports_vision: bool            # Image input
    cost_per_1m_input: float         # USD per 1M input tokens (0.0 for subscription)
    cost_per_1m_output: float        # USD per 1M output tokens (0.0 for subscription)
```

**Registry source:** `config/models.yaml` extended with capability metadata:

```yaml
models:
  claude-sonnet-4-6:
    provider: anthropic
    context_window: 200000
    max_output_tokens: 64000
    supports_json_schema: true
    supports_reasoning: true
    supports_vision: true
    cost_per_1m_input: 3.00
    cost_per_1m_output: 15.00
  
  gpt-5.5:
    provider: openai
    context_window: 1000000
    max_output_tokens: 100000
    supports_json_schema: true
    supports_reasoning: false
    supports_vision: true
    cost_per_1m_input: 2.00
    cost_per_1m_output: 8.00
```

**Files to modify:**

| File | Change |
|------|--------|
| `config/models.yaml` | Add `models:` section with full metadata per model |
| `src/security_review/model_registry.py` | **New:** `ModelCapabilities` dataclass, `get_capabilities(model_string)` loader |
| `src/security_review/model_capabilities.py` | Replace `supports_native_json()` with `get_capabilities(model).supports_json_schema` |
| `src/security_review/providers.py` | Attach capabilities to built model via registry lookup |
| `src/security_review/budget.py` | Use `capabilities.cost_per_1m_*` instead of `config/pricing.yaml` |
| `config/pricing.yaml` | **Delete** (data moves to `models.yaml`) |
| `src/security_review/passes/holistic.py` | Use `capabilities.context_window` for batch sizing |

**Implementation steps:**

1. Define `ModelCapabilities` dataclass in new `model_registry.py`.
2. Extend `config/models.yaml` with a `models:` section containing capability metadata for all supported models.
3. Implement `get_capabilities(model_string: str) -> ModelCapabilities` that resolves aliases then looks up metadata.
4. Refactor `supports_native_json()` to delegate to `get_capabilities(...).supports_json_schema`.
5. Refactor `CostTracker` to use registry costs instead of `pricing.yaml`.
6. In `passes/holistic.py`, use `capabilities.context_window` when computing `max_tokens_per_batch` headroom.
7. Delete `config/pricing.yaml` after confirming no remaining references.

**Acceptance:** `get_capabilities("copilot:claude-sonnet")` returns a `ModelCapabilities` with `supports_json_schema=False`, `context_window=200000`. Unit tests cover all registered models.

---

## Priority 3: Context Overflow Detection

**Goal:** Detect context-length errors from all providers and surface actionable diagnostics instead of opaque tracebacks.

**Problem:** When a holistic batch exceeds the model's context window, the SDK raises a provider-specific error (Anthropic: `InvalidRequestError`, OpenAI: `BadRequestError`, Copilot: timeout/hang). The pass logs a generic exception and moves on. No automatic recovery.

**New file:** `src/security_review/overflow.py`

**Implementation:**

```python
import re

_OVERFLOW_PATTERNS = [
    # Anthropic
    re.compile(r"prompt is too long|max.*token.*limit.*exceeded", re.IGNORECASE),
    # OpenAI
    re.compile(r"maximum context length|tokens.*exceeds.*model.*maximum", re.IGNORECASE),
    # Generic
    re.compile(r"context.*(window|length).*exceed|input.*too.*long", re.IGNORECASE),
]


def is_context_overflow(error: Exception) -> bool:
    """Return True if the error indicates a context window overflow."""
    msg = str(error)
    return any(p.search(msg) for p in _OVERFLOW_PATTERNS)
```

**Files to modify:**

| File | Change |
|------|--------|
| `src/security_review/overflow.py` | **New:** `is_context_overflow()`, `_OVERFLOW_PATTERNS` |
| `src/security_review/passes/holistic.py` | Catch overflow → split batch → retry with smaller file set |
| `src/security_review/passes/config_review.py` | Catch overflow → reduce file count → retry |
| `src/security_review/passes/triage.py` | Catch overflow → log (triage is single-file, so this is a model limit issue) |

**Implementation steps:**

1. Create `overflow.py` with regex patterns for known provider error messages.
2. In `passes/holistic.py` `_execute_check()`, wrap the `agent.run()` in a try/except that calls `is_context_overflow(e)`. If true:
   - Log a warning with the batch size and model context window.
   - If the batch has >1 file, split in half and retry each sub-batch.
   - If single file, truncate to `capabilities.context_window * 0.8` chars and retry once.
3. In `passes/config_review.py`, apply the same pattern for multi-file batches.
4. In `passes/triage.py`, just log a clear diagnostic (triage is single-finding, can't split further).

**Acceptance:** A test with `FunctionModel` that raises an overflow-style error triggers the split logic. Integration test with an intentionally oversized batch succeeds via auto-splitting.

---

## Priority 4: Consistent Retry with Delay Cap

**Goal:** All providers get uniform retry behaviour with exponential backoff and a configurable max delay cap.

**Problem:** Only `CopilotModel` has retry logic (2 attempts, fixed backoff). Other providers rely on SDK defaults (Anthropic SDK retries 2x by default, OpenAI SDK retries 2x). There's no cap on server-suggested `Retry-After` delays, and no unified configuration.

**New config field in `ProviderConfig`:**

```python
class ProviderConfig(BaseModel, extra="forbid"):
    max_concurrent: int = Field(default=5, ge=1, le=100)
    session_timeout: float = Field(default=90.0, ge=10.0, le=600.0)
    backoff_seconds: float = Field(default=10.0, ge=1.0, le=60.0)
    max_retries: int = Field(default=2, ge=0, le=5)            # NEW
    max_retry_delay: float = Field(default=60.0, ge=5.0, le=300.0)  # NEW: cap in seconds
```

**New file:** `src/security_review/retry.py`

**Implementation:**

```python
import asyncio
import structlog
from security_review.config_schema import ProviderConfig

logger = structlog.get_logger()

_RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 529}


def is_retryable(error: Exception) -> bool:
    """Determine if an error is transient and worth retrying."""
    msg = str(error).lower()
    if any(code_str in msg for code_str in ("429", "500", "502", "503", "529")):
        return True
    if "timeout" in msg or "timed out" in msg:
        return True
    if "overloaded" in msg or "rate limit" in msg:
        return True
    return False


async def with_retry(coro_factory, *, provider_config: ProviderConfig, operation: str):
    """Execute an async operation with exponential backoff and delay cap.
    
    coro_factory: callable that returns a new coroutine each invocation.
    """
    last_error = None
    for attempt in range(1 + provider_config.max_retries):
        try:
            return await coro_factory()
        except Exception as e:
            last_error = e
            if attempt >= provider_config.max_retries or not is_retryable(e):
                raise
            delay = min(
                provider_config.backoff_seconds * (2 ** attempt),
                provider_config.max_retry_delay,
            )
            logger.warning(
                "retry.attempt",
                operation=operation,
                attempt=attempt + 1,
                max_retries=provider_config.max_retries,
                delay_seconds=delay,
                error=str(e)[:200],
            )
            await asyncio.sleep(delay)
    raise last_error
```

**Files to modify:**

| File | Change |
|------|--------|
| `src/security_review/config_schema.py` | Add `max_retries`, `max_retry_delay` to `ProviderConfig` |
| `src/security_review/retry.py` | **New:** `is_retryable()`, `with_retry()` |
| `src/security_review/passes/triage.py` | Wrap `agent.run()` in `with_retry()` |
| `src/security_review/passes/holistic.py` | Wrap `agent.run()` in `with_retry()` |
| `src/security_review/passes/config_review.py` | Wrap `agent.run()` in `with_retry()` |
| `config/settings/security_review.yaml` | Add `max_retries` and `max_retry_delay` defaults per provider |

**Implementation steps:**

1. Add `max_retries` and `max_retry_delay` to `ProviderConfig` schema.
2. Create `retry.py` with `is_retryable()` (pattern matching on error messages/codes) and `with_retry()` (exponential backoff with delay cap).
3. In each pass, wrap the `agent.run()` call:
   ```python
   result = await with_retry(
       lambda: triage_agent.run(prompt, model=model, ...),
       provider_config=provider_cfg,
       operation=f"triage:{rule_id}",
   )
   ```
4. Remove the custom retry logic from `CopilotModel._execute_request` — it's now handled uniformly.
5. Update YAML config with sensible defaults per provider.

**Acceptance:** A test simulating a 429 error retries with backoff. A test with `Retry-After: 600` caps delay at `max_retry_delay` (60s default). The pipeline doesn't stall for more than `max_retry_delay` on any single retry.

---

## Priority 5: Lazy Provider Imports

**Goal:** Provider SDK packages are only imported when actually used, preventing startup crashes and reducing import time.

**Problem:** If a user configures `copilot:claude-sonnet` but hasn't installed the `github-copilot-sdk` package, the import inside `build_model()` fails immediately. More importantly, if we import *all* provider modules at the top of `providers.py`, any missing SDK crashes the whole process even for unrelated providers.

**Currently:** Each provider branch in `build_model()` already uses local imports (good). The issue is that error messages are generic `ImportError` tracebacks rather than actionable user guidance.

**Files to modify:**

| File | Change |
|------|--------|
| `src/security_review/providers.py` | Wrap each provider's imports in try/except with clear error messages |
| `src/security_review/model_providers.py` | Already uses local imports (no change needed) |

**Implementation steps:**

1. In `build_model()`, wrap each provider's import block:
   ```python
   elif provider == "copilot":
       try:
           from security_review.copilot_model import CopilotModel
       except ImportError as e:
           raise ConfigurationError(
               f"Provider 'copilot' requires the github-copilot-sdk package. "
               f"Install with: pip install github-copilot-sdk\n"
               f"Original error: {e}",
               code="SYS_DEPENDENCY_MISSING",
           )
       inner = CopilotModel(model_id=model_name, ...)
   ```
2. Apply the same pattern for `claude` (requires `claude-agent-sdk`) and `codex` (requires `codex-app-server`).
3. Ensure `openai` and `anthropic` also get clear messages if their SDKs are missing.
4. Add a `--check-providers` flag to `scar.py` that attempts to import all configured providers and reports availability.

**Acceptance:** Running with `copilot:claude-sonnet` without the Copilot SDK installed produces: `ConfigurationError: Provider 'copilot' requires the github-copilot-sdk package. Install with: pip install github-copilot-sdk`.

---

## Priority 6: Transport-Protocol Abstraction

**Goal:** Separate "wire protocol" (how bytes are sent/received) from "provider brand" (who authenticates and what URL to hit). This allows N providers to share a single transport implementation.

**Problem:** Today, adding a new OpenAI-compatible provider (Azure OpenAI, Groq, Together, xAI, Ollama) requires either a new `elif` branch in `build_model()` or shoehorning it into the `openai:` path with URL hacks. Pi-mono solves this with a `KnownApi` enum + `api-registry` pattern.

**Architecture (inspired by pi-mono):**

```
┌────────────────────────────────────────────────────────────────────┐
│  config/models.yaml                                                │
│                                                                    │
│  models:                                                           │
│    claude-sonnet-4-6:                                              │
│      transport: anthropic-messages     ◄── wire protocol           │
│      provider: anthropic               ◄── brand / auth            │
│      base_url: null                    ◄── override for proxies    │
│                                                                    │
│    gpt-5.5-azure:                                                  │
│      transport: openai-chat            ◄── same transport as gpt   │
│      provider: azure-openai            ◄── different auth/URL      │
│      base_url: https://my.azure.com/v1                             │
│                                                                    │
│    claude-sonnet-copilot:                                          │
│      transport: copilot-sessions       ◄── Copilot SDK transport   │
│      provider: copilot                                             │
└────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────┐
│  Transport Registry (transport_registry.py)                        │
│                                                                    │
│  "openai-chat"          → OpenAIChatTransport   (openai SDK)       │
│  "anthropic-messages"   → AnthropicTransport    (anthropic SDK)    │
│  "copilot-sessions"     → CopilotTransport      (copilot SDK)      │
│  "claude-agent"         → ClaudeAgentTransport  (claude-agent-sdk)  │
│  "codex-subprocess"     → CodexTransport        (codex app-server)  │
└────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────┐
│  Auth Registry (auth_registry.py)                                  │
│                                                                    │
│  "anthropic"     → ANTHROPIC_API_KEY env var                       │
│  "openai"        → OPENAI_API_KEY env var                          │
│  "azure-openai"  → AZURE_OPENAI_API_KEY + endpoint                │
│  "copilot"       → Copilot SDK OAuth                               │
│  "claude"        → Claude Max/Pro OAuth                            │
│  "codex"         → Codex subscription OAuth                        │
│  "groq"          → GROQ_API_KEY env var (transport: openai-chat)   │
└────────────────────────────────────────────────────────────────────┘
```

**Key Insight:** `transport` determines *which SDK to use*. `provider` determines *how to authenticate* and *what base URL*. Multiple providers can share one transport (Groq, Azure, xAI all use `openai-chat`).

**New files:**

| File | Purpose |
|------|---------|
| `src/security_review/transports/__init__.py` | Package init |
| `src/security_review/transports/base.py` | `Transport` protocol (abstract base) |
| `src/security_review/transports/openai_chat.py` | OpenAI Chat Completions transport |
| `src/security_review/transports/anthropic_messages.py` | Anthropic Messages API transport |
| `src/security_review/transports/copilot_sessions.py` | Move from `copilot_model.py` |
| `src/security_review/transports/claude_agent.py` | Move from `claude_model.py` |
| `src/security_review/transports/codex_subprocess.py` | Move from `codex_model.py` |
| `src/security_review/transport_registry.py` | Registry: transport name → lazy-loaded Transport class |
| `src/security_review/auth_registry.py` | Registry: provider name → auth resolver |

**Transport protocol (abstract base):**

```python
from __future__ import annotations
from typing import Protocol
from pydantic_ai.models import Model

class Transport(Protocol):
    """Wire-protocol adapter that builds a PydanticAI Model."""

    @staticmethod
    def build(
        model_id: str,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        **kwargs,
    ) -> Model:
        """Construct a PydanticAI Model for this transport."""
        ...
```

**Transport Registry:**

```python
from __future__ import annotations
from typing import Callable
from security_review.transports.base import Transport

_REGISTRY: dict[str, Callable[[], type[Transport]]] = {}


def register_transport(name: str, factory: Callable[[], type[Transport]]) -> None:
    _REGISTRY[name] = factory


def get_transport(name: str) -> type[Transport]:
    if name not in _REGISTRY:
        raise ConfigurationError(f"Unknown transport: {name}")
    return _REGISTRY[name]()


# Lazy registration — SDK not imported until first use
register_transport("openai-chat", lambda: _load("security_review.transports.openai_chat", "OpenAIChatTransport"))
register_transport("anthropic-messages", lambda: _load("security_review.transports.anthropic_messages", "AnthropicTransport"))
register_transport("copilot-sessions", lambda: _load("security_review.transports.copilot_sessions", "CopilotTransport"))
register_transport("claude-agent", lambda: _load("security_review.transports.claude_agent", "ClaudeAgentTransport"))
register_transport("codex-subprocess", lambda: _load("security_review.transports.codex_subprocess", "CodexTransport"))
```

**Refactored `build_model()`:**

```python
def build_model(model_string: str, *, llm_config=None):
    """Build a PydanticAI Model via transport + auth registries."""
    from pydantic_ai.models.concurrency import ConcurrencyLimitedModel
    from security_review.config_schema import LLMConfig
    from security_review.model_registry import get_capabilities
    from security_review.transport_registry import get_transport
    from security_review.auth_registry import resolve_auth

    provider, _, model_name = model_string.partition(":")
    model_name = resolve_model_name(provider, model_name)
    
    cfg = llm_config or LLMConfig()
    provider_cfg = cfg.provider_config(provider)
    
    # Look up capabilities (includes transport type)
    capabilities = get_capabilities(provider, model_name)
    
    # Get transport implementation (lazy import)
    transport_cls = get_transport(capabilities.transport)
    
    # Resolve auth for this provider
    auth = resolve_auth(provider)
    
    # Build the inner PydanticAI Model
    inner = transport_cls.build(
        model_name,
        base_url=capabilities.base_url,
        api_key=auth.api_key,
        session_timeout=provider_cfg.session_timeout,
        backoff_seconds=provider_cfg.backoff_seconds,
    )
    
    # Wrap with concurrency limiter
    limiter = _get_limiter(provider, provider_cfg.max_concurrent)
    return ConcurrencyLimitedModel(inner, limiter=limiter)
```

**Migration steps:**

1. **Create branch** `feature/transport-abstraction`.
2. **Create backup** of `providers.py`, `model_providers.py`, `copilot_model.py`, `claude_model.py`, `codex_model.py`.
3. **Create** `src/security_review/transports/` package with `base.py`.
4. **Move** `CopilotModel` logic into `transports/copilot_sessions.py` (keep PydanticAI `Model` interface).
5. **Move** `ClaudeModel` logic into `transports/claude_agent.py`.
6. **Move** `CodexModel` logic into `transports/codex_subprocess.py`.
7. **Create** `transports/openai_chat.py` wrapping PydanticAI's `OpenAIModel`.
8. **Create** `transports/anthropic_messages.py` wrapping PydanticAI's `AnthropicModel`.
9. **Create** `transport_registry.py` with lazy loading.
10. **Create** `auth_registry.py` that consolidates logic from `model_providers.py`.
11. **Refactor** `providers.py` `build_model()` to use the registry pattern (remove `if/elif` chain).
12. **Extend** `config/models.yaml` with `transport` field per model.
13. **Add** Azure OpenAI as proof-of-concept (reuses `openai-chat` transport with different auth).
14. **Run** `pytest tests/unit/ -v` — all tests must pass.
15. **Delete** old files: `model_providers.py`, `copilot_model.py`, `claude_model.py`, `codex_model.py`.
16. **Run** full integration test suite.
17. **Merge** branch.

**Acceptance:**
- Adding Azure OpenAI requires only: a new entry in `models.yaml` (with `transport: openai-chat`, `provider: azure-openai`) and a new auth resolver in `auth_registry.py`. Zero new transport code.
- All existing `copilot:`, `anthropic:`, `openai:`, `claude:`, `codex:` configurations continue to work unchanged.
- `pytest tests/unit/ -v` passes with no regressions.

---

## Dependency Graph

```
Priority 1 (output_retries)     ─── independent, do first
Priority 2 (model capabilities) ─── independent, do in parallel with 1
Priority 3 (overflow detection) ─── depends on Priority 2 (uses context_window)
Priority 4 (retry layer)        ─── independent, but pairs well with 3
Priority 5 (lazy imports)       ─── independent, trivial
Priority 6 (transport abstraction) ─── depends on 2 + 5 being done; subsumes parts of 4
```

**Recommended execution order:** 1 → 2 → 5 → 3 → 4 → 6

---

## Risk Assessment

| Priority | Risk | Mitigation |
|----------|------|------------|
| 1 | Low — simple config wiring | Unit test with TestModel |
| 2 | Medium — changing models.yaml format | Backward-compat: keep existing `aliases`/`providers` sections |
| 3 | Low — additive error handling | Regex patterns may miss new error formats; log unrecognised errors |
| 4 | Medium — retry interaction with PydanticAI's built-in retry | Disable PydanticAI retry for transport-level errors; keep it for validation |
| 5 | Low — already mostly done in current code | Just improve error messages |
| 6 | High — large refactor touching auth, transport, model construction | Branch + backup + incremental migration; old paths kept until fully tested |
