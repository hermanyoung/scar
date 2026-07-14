"""Tests for the uniform transport-retry wrapper (Plan 020 Phase 3)."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart
from pydantic_ai.models import Model, ModelRequestParameters
from pydantic_ai.usage import RequestUsage

from security_review.config import load_config
from security_review.errors import ConfigurationError
from security_review.retry_model import RetryingModel, _is_empty_response


class AuthenticationError(Exception):
    """Same type name providers raise — is_fatal_error matches on the name."""


def _text_response(text: str = "ok") -> ModelResponse:
    return ModelResponse(
        parts=[TextPart(content=text)],
        usage=RequestUsage(),
        model_name="stub-model",
        timestamp=datetime.now(timezone.utc),
    )


class _StubModel(Model):
    """Scripted model: each request() pops the next action (Exception or response)."""

    def __init__(self, script: list):
        super().__init__()
        self._script = list(script)
        self.calls = 0

    @property
    def model_name(self) -> str:
        return "stub-model"

    @property
    def system(self) -> str:
        return "stub"

    async def request(self, messages, model_settings, model_request_parameters):
        action = self._script[min(self.calls, len(self._script) - 1)]
        self.calls += 1
        if isinstance(action, Exception):
            raise action
        return action


def _patch_sleep(monkeypatch) -> list[float]:
    """Replace asyncio.sleep inside retry_model with a recorder (fake clock)."""
    delays: list[float] = []

    async def _fake_sleep(seconds):
        delays.append(seconds)

    monkeypatch.setattr("security_review.retry_model.asyncio.sleep", _fake_sleep)
    return delays


async def _drive(model) -> ModelResponse:
    return await model.request([], None, ModelRequestParameters())


# -- Transient exceptions ---------------------------------------------------------


async def test_retry_recovers_from_transient_timeouts_with_backoff(monkeypatch):
    delays = _patch_sleep(monkeypatch)
    stub = _StubModel([TimeoutError("t1"), TimeoutError("t2"), _text_response("recovered")])
    model = RetryingModel(stub, backoff_seconds=10.0, provider="copilot")

    import structlog.testing
    with structlog.testing.capture_logs() as logs:
        response = await _drive(model)

    assert response.parts[0].content == "recovered"
    assert stub.calls == 3
    # Exponential backoff seeded from backoff_seconds.
    assert delays == [10.0, 20.0]
    retry_logs = [l for l in logs if l["event"] == "model.retry"]
    assert len(retry_logs) == 2
    assert retry_logs[0]["attempt"] == 1 and retry_logs[1]["attempt"] == 2


async def test_retry_exhaustion_reraises_the_exception(monkeypatch):
    delays = _patch_sleep(monkeypatch)
    stub = _StubModel([TimeoutError("always")])
    model = RetryingModel(stub, backoff_seconds=1.0, provider="openai", max_attempts=3)

    with pytest.raises(TimeoutError):
        await _drive(model)
    assert stub.calls == 3
    assert len(delays) == 2


async def test_backoff_delay_is_bounded_by_max_delay(monkeypatch):
    delays = _patch_sleep(monkeypatch)
    stub = _StubModel([TimeoutError("t")] * 4 + [_text_response()])
    model = RetryingModel(stub, backoff_seconds=50.0, provider="openai",
                          max_attempts=5, max_delay_seconds=120.0)

    await _drive(model)
    # 50 -> 100 -> 200(cap 120) -> 400(cap 120)
    assert delays == [50.0, 100.0, 120.0, 120.0]


# -- Fatal / overflow errors are never retried ---------------------------------------


async def test_authentication_error_not_retried(monkeypatch):
    delays = _patch_sleep(monkeypatch)
    stub = _StubModel([AuthenticationError("bad token")])
    model = RetryingModel(stub, backoff_seconds=1.0, provider="anthropic")

    with pytest.raises(AuthenticationError):
        await _drive(model)
    assert stub.calls == 1
    assert delays == []


async def test_configuration_error_not_retried(monkeypatch):
    _patch_sleep(monkeypatch)
    stub = _StubModel([ConfigurationError("missing key", code="SYS_CONFIG_INVALID")])
    model = RetryingModel(stub, backoff_seconds=1.0, provider="openai")

    with pytest.raises(ConfigurationError):
        await _drive(model)
    assert stub.calls == 1


async def test_context_overflow_error_not_retried(monkeypatch):
    # Addendum A.6: overflow re-raises immediately so the pass-level
    # halve-and-retry handles it — retrying an oversized prompt is wasted spend.
    delays = _patch_sleep(monkeypatch)
    stub = _StubModel([RuntimeError("prompt is too long: 210000 tokens")])
    model = RetryingModel(stub, backoff_seconds=1.0, provider="anthropic")

    with pytest.raises(RuntimeError):
        await _drive(model)
    assert stub.calls == 1
    assert delays == []


# -- Empty responses -----------------------------------------------------------------


async def test_empty_response_triggers_retry_then_returns_success(monkeypatch):
    delays = _patch_sleep(monkeypatch)
    stub = _StubModel([_text_response(""), _text_response("content")])
    model = RetryingModel(stub, backoff_seconds=5.0, provider="copilot")

    response = await _drive(model)
    assert response.parts[0].content == "content"
    assert stub.calls == 2
    assert delays == [5.0]


async def test_empty_response_exhaustion_returns_empty_not_raise(monkeypatch):
    _patch_sleep(monkeypatch)
    stub = _StubModel([_text_response("")])
    model = RetryingModel(stub, backoff_seconds=1.0, provider="copilot", max_attempts=2)

    response = await _drive(model)
    # Returned (not raised) so existing parse-fail handling still runs.
    assert response.parts[0].content == ""
    assert stub.calls == 2


def test_tool_call_only_response_is_not_empty():
    # Native-JSON providers return tool-call parts for structured output —
    # those must never be classified as empty (and retried).
    response = ModelResponse(
        parts=[ToolCallPart(tool_name="final_result", args="{}")],
        usage=RequestUsage(),
        model_name="stub-model",
        timestamp=datetime.now(timezone.utc),
    )
    assert _is_empty_response(response) is False
    assert _is_empty_response(_text_response("")) is True
    assert _is_empty_response(_text_response("   \n")) is True
    assert _is_empty_response(_text_response("hi")) is False


# -- build_model wiring: all five providers -------------------------------------------


@pytest.mark.parametrize("provider,model_string", [
    ("copilot", "copilot:claude-opus"),
    ("claude", "claude:claude-sonnet"),
    ("codex", "codex:gpt-5.4"),
    ("anthropic", "anthropic:claude-opus"),
    ("openai", "openai:gpt-5.5"),
])
def test_build_model_wraps_every_provider_in_retrying_model(
    provider: str, model_string: str, monkeypatch,
):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key-not-real")
    from security_review.providers import build_model

    cfg = load_config(None)
    model = build_model(model_string, llm_config=cfg.llm)

    assert isinstance(model, RetryingModel)
    # backoff_seconds from security_review.yaml demonstrably drives the policy.
    assert model._backoff_seconds == cfg.llm.provider_config(provider).backoff_seconds


async def test_configured_backoff_seconds_drives_the_delay(monkeypatch):
    # End-to-end: the YAML value (copilot: 10.0) is the first sleep duration.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")
    from security_review.providers import build_model

    cfg = load_config(None)
    model = build_model("copilot:claude-opus", llm_config=cfg.llm)
    stub = _StubModel([TimeoutError("t"), _text_response()])
    model.wrapped = stub  # bypass the real transport, keep the retry policy

    delays = _patch_sleep(monkeypatch)
    await _drive(model)

    assert delays == [cfg.llm.provider_config("copilot").backoff_seconds]
