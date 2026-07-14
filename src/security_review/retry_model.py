"""Uniform, config-driven transport retry for all LLM providers.

RetryingModel activates ``providers.<name>.backoff_seconds`` — previously
read only by the Copilot adapter — as a single retry policy applied by
build_model() to every provider (openai, anthropic, copilot, claude, codex).

Retries when either:
  1. the wrapped model raises a **non-fatal** exception — never auth/config/
     model-not-available (errors.is_fatal_error), and never context-overflow
     errors (errors.is_context_overflow_error): the pass-level
     halve-and-retry (019 WP-F) owns those, and retrying an oversized prompt
     N times is N× wasted spend; or
  2. the ModelResponse carries no usable content (the empty-response case
     that was previously returned as success and lost at parse time — the
     "Copilot returns 0 findings intermittently" bug).

Backoff is exponential from backoff_seconds with a bounded attempt count
and delay ceiling (mirrors the reference harness's bounded retry budget).
On exhaustion: the exception case re-raises; the empty case returns the
empty response so existing parse-fail handling still runs.

Applied as the OUTERMOST wrapper (outside ConcurrencyLimitedModel), so each
retry re-acquires the provider concurrency slot cleanly. CopilotModel keeps
its internal 2-attempt fresh-session timeout loop — a deliberate, bounded
overlap (belt-and-suspenders) documented here rather than removed silently.
"""
from __future__ import annotations

import asyncio

import structlog
from pydantic_ai.messages import ModelMessage, ModelResponse, TextPart
from pydantic_ai.models import Model, ModelRequestParameters
from pydantic_ai.models.wrapper import WrapperModel
from pydantic_ai.settings import ModelSettings

from security_review.errors import is_context_overflow_error, is_fatal_error

logger = structlog.get_logger()

# Bounded retry budget: total attempts and a ceiling on the exponential delay.
MAX_ATTEMPTS = 5
MAX_DELAY_SECONDS = 120.0


class RetryingModel(WrapperModel):
    """Retry wrapper: transient failures and empty responses, with backoff."""

    def __init__(
        self,
        wrapped: Model,
        *,
        backoff_seconds: float,
        provider: str,
        max_attempts: int = MAX_ATTEMPTS,
        max_delay_seconds: float = MAX_DELAY_SECONDS,
    ):
        super().__init__(wrapped)
        self._backoff_seconds = backoff_seconds
        self._provider = provider
        self._max_attempts = max_attempts
        self._max_delay_seconds = max_delay_seconds

    async def request(
        self,
        messages: list[ModelMessage],
        model_settings: ModelSettings | None,
        model_request_parameters: ModelRequestParameters,
    ) -> ModelResponse:
        delay = self._backoff_seconds
        for attempt in range(1, self._max_attempts + 1):
            try:
                response = await self.wrapped.request(
                    messages, model_settings, model_request_parameters,
                )
            except Exception as e:
                logger.warning(
                    "model.request_failed",
                    provider=self._provider,
                    model=self.model_name,
                    attempt=attempt,
                    error=str(e),
                    error_type=type(e).__name__,
                )
                # Fail-fast is preserved: fatal errors are never retried, and
                # overflow re-raises immediately for the pass-level halving.
                if is_fatal_error(e) or is_context_overflow_error(e) or attempt >= self._max_attempts:
                    raise
                delay = await self._backoff(attempt, delay, reason=f"{type(e).__name__}: {e}")
                continue

            if not _is_empty_response(response):
                return response
            if attempt >= self._max_attempts:
                # Exhausted on empty — return it so the existing parse-fail
                # handling (triage/holistic classify paths) still runs.
                logger.warning(
                    "model.empty_response_exhausted",
                    provider=self._provider,
                    model=self.model_name,
                    attempts=attempt,
                )
                return response
            delay = await self._backoff(attempt, delay, reason="empty_response")

        raise AssertionError("unreachable: retry loop always returns or raises")

    async def _backoff(self, attempt: int, delay: float, *, reason: str) -> float:
        """Log, sleep the bounded delay, and return the next (doubled) delay."""
        bounded = min(delay, self._max_delay_seconds)
        logger.warning(
            "model.retry",
            provider=self._provider,
            model=self.model_name,
            attempt=attempt,
            max_attempts=self._max_attempts,
            delay_seconds=round(bounded, 1),
            reason=reason,
        )
        await asyncio.sleep(bounded)
        return delay * 2


def _is_empty_response(response: ModelResponse) -> bool:
    """True when the response carries no usable content.

    Only text is judged: a response whose parts are all empty/whitespace
    TextParts (or that has no parts) failed at the transport level. Any
    non-text part (tool call, thinking) counts as content — native-JSON
    providers return tool-call parts for structured output and must never
    be treated as empty.
    """
    for part in response.parts:
        if isinstance(part, TextPart):
            if part.content and part.content.strip():
                return False
        else:
            return False
    return True
