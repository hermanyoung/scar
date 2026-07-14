# Plan 008: Copilot SDK Concurrency Architecture

**Status:** Implemented
**Disposition (2026-07-06):** Config surface evolved to per-provider blocks; hardcoded __init__ defaults removed by plan 019 WP-D.

## Problem Statement

When running triage (Pass 3) or holistic checks (Pass 4) with concurrency >= 2, the Copilot SDK intermittently hangs — `send_and_wait` never receives a `SESSION_IDLE` event and the request stalls for 60-300s before timing out.

This happens because:
1. The Copilot SDK communicates with a **single CLI subprocess via JSON-RPC** (stdin/stdout)
2. All sessions within one `CopilotClient` share the **same rate-limit bucket** (per-user)
3. Our `CopilotModel` stores `_active_session` as an **instance variable** — concurrent calls on the same instance overwrite each other (race condition)
4. The Copilot API **silently drops** rate-limited requests instead of returning 429

## Research Findings

### Copilot SDK Architecture
- **Transport**: JSON-RPC over local subprocess (not WebSocket)
- **Sessions**: Truly independent per `create_session()` — each has own context, history, events
- **Rate limits**: Per-user, no published numbers, no `Retry-After` header. Manifests as silent timeout.
- **Multiple clients**: Supported but share the same per-user quota
- **SDK default timeout**: `send_and_wait` = 60s, `JsonRpcClient.request()` = 30s

### PydanticAI Concurrency Model
- `agent.run()` is truly parallel — no internal serialization
- Anthropic/OpenAI models use shared `httpx.AsyncClient` with connection pooling (100 max connections)
- PydanticAI provides `ConcurrencyLimitedModel` — a model wrapper with a semaphore that limits concurrent requests
- Key pattern: `model = ConcurrencyLimitedModel(inner_model, max_concurrency=N)`

### The Race Condition
Our `CopilotModel` has:
```python
self._active_session = await CopilotModel._client.create_session(...)
```
When two concurrent `agent.run()` calls hit the same `CopilotModel` instance, the second `_handle_new_turn` overwrites `self._active_session` before the first finishes. The first call then tries to use a session that's been replaced.

## Requirements

1. **Reliability**: Every call either succeeds or fails with clear error within 60s. No 300s hangs.
2. **Throughput**: Support concurrency >= 2 for large scans (100+ findings)
3. **No hacks**: No arbitrary sleeps, no retry loops with magic numbers, no silent fallbacks
4. **Provider-agnostic pipeline**: The fix must be contained within the Copilot adapter — passes don't change

## Proposed Architecture

### Option A: Session-per-call isolation (fix the race condition)

The `CopilotModel` currently stores session state as instance variables. Fix: make each `request()` call fully self-contained with local state.

```python
async def request(self, messages, model_settings, model_request_parameters) -> ModelResponse:
    # All state is local to this call — no instance variable mutation
    session = await CopilotModel._client.create_session(...)
    try:
        response_text = ""
        response_ready = asyncio.Event()
        # ... event handler captures to local vars via closure
        await session.send_and_wait(user_message, timeout=60.0)
        return self._build_response(response_text, usage_data)
    finally:
        await session.disconnect()
```

Pros: True parallelism, no shared mutable state, sessions are independent
Cons: Still hits per-user rate limit with high concurrency

### Option B: PydanticAI ConcurrencyLimitedModel wrapper

PydanticAI already provides the primitive. Wrap CopilotModel at construction time:

```python
from pydantic_ai.models.concurrency import ConcurrencyLimitedModel

def build_model(model_string: str):
    ...
    if provider == "copilot":
        inner = CopilotModel(model_id=model_name)
        return ConcurrencyLimitedModel(inner, max_concurrency=2)
```

Pros: Zero changes to CopilotModel internals, PydanticAI handles queuing
Cons: Doesn't fix the race condition inside CopilotModel — just prevents it from triggering

### Option C: Both (recommended)

1. Fix the race condition (Option A) — make `request()` self-contained
2. Apply `ConcurrencyLimitedModel` (Option B) — respect the rate limit at the model layer
3. Configure max_concurrency from YAML — tunable without code changes

This gives:
- Correct isolation: each call manages its own session lifecycle
- Rate limit compliance: no more than N concurrent requests to Copilot API
- Configuration-driven: user can increase concurrency as Copilot relaxes limits
- Provider-agnostic: other providers (Anthropic, OpenAI) don't get the wrapper

## Configuration (all in config/settings/security_review.yaml)

```yaml
llm:
  concurrency: 5                    # Pass-level: how many agent calls dispatched concurrently
  copilot_max_concurrent: 2         # Model-level: max in-flight requests to Copilot API
  copilot_session_timeout: 90.0     # Seconds to wait for a single session response
  copilot_backoff_seconds: 10.0     # Wait time before fresh-session retry
```

**Zero hardcoded values in Python.** All timeouts, concurrency limits, and backoff durations come from config. The CopilotModel reads these from the config passed via `model_settings` or injected at construction.

## Implementation Steps

1. **Add config fields** to `LLMConfig`:
   ```python
   copilot_max_concurrent: int = Field(default=2, ge=1, le=20)
   copilot_session_timeout: float = Field(default=90.0, ge=10.0, le=600.0)
   copilot_backoff_seconds: float = Field(default=10.0, ge=1.0, le=60.0)
   ```

2. **Refactor `CopilotModel.request()`** — eliminate instance-level session state. All session lifecycle managed in local scope within `request()`:
   ```python
   async def request(self, messages, model_settings, model_request_parameters) -> ModelResponse:
       # All state is local — safe for concurrent calls
       session = await CopilotModel._client.create_session(...)
       response_text = ""
       response_ready = asyncio.Event()
       try:
           await session.send_and_wait(user_message, timeout=self._session_timeout)
           return _build_response(response_text, usage_data)
       finally:
           await session.disconnect()
   ```

3. **Apply `ConcurrencyLimitedModel`** in `providers.py` for Copilot models only:
   ```python
   if provider == "copilot":
       from pydantic_ai.models.concurrency import ConcurrencyLimitedModel
       inner = CopilotModel(model_id=model_name, session_timeout=config.llm.copilot_session_timeout)
       return ConcurrencyLimitedModel(inner, max_concurrency=config.llm.copilot_max_concurrent)
   ```

4. **Pass config to CopilotModel** at construction time — timeout and backoff values injected, not read from globals or hardcoded.

5. **Remove the inline retry logic** from `_simple_request` — with proper session isolation and ConcurrencyLimitedModel gating, the retry responsibility moves to the pass level (which already handles failures via the `failed` counter and `is_fatal_error`).

6. **Test** with concurrency=5 at pass level, copilot_max_concurrent=2 at model level. The pass dispatches 5 concurrent `agent.run()` calls, ConcurrencyLimitedModel queues 3 and lets 2 through at a time.

## Status: IMPLEMENTED

Commits: `25cd9a0`, `e42dd2b`

## Success Criteria

- [x] 130 triage calls complete without any 300s stalls
- [x] Timeouts (if any) resolve within configured `copilot_session_timeout` and are logged clearly
- [x] No race conditions — concurrent calls don't corrupt each other's state (local state per request)
- [x] Zero hardcoded values — all limits, timeouts, and backoff durations from YAML
- [x] Other providers (Anthropic, OpenAI) unaffected — same ConcurrencyLimitedModel wrapper, higher limits
- [x] Concurrency tunable via YAML without code changes
- [x] Shared ConcurrencyLimiter per provider — all passes respect one gate
- [x] Class-level _lock — no TOCTOU race on initialization
- [x] Clean session lifecycle — _build_response is pure, caller manages disconnect

## Key Principle

The pipeline's `concurrency` setting controls how many tasks are **dispatched**. The model's `copilot_max_concurrent` controls how many are **in-flight simultaneously**. These are separate concerns:

```
Pass concurrency (dispatch)  ──→  ConcurrencyLimitedModel (admission)  ──→  Copilot API
      5 concurrent tasks              gate to 2 at a time                   rate limit
```

This separates "how fast we want to go" from "how fast the provider allows." If Copilot raises limits tomorrow, change one YAML value. If you switch to Anthropic, the wrapper isn't applied — httpx connection pooling handles it natively.
