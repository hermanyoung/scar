"""Tests for LLM preflight validation (Plan 018 WP4)."""
from __future__ import annotations

import pytest
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.models.test import TestModel

from security_review.budget import CostTracker
from security_review.config import load_config
from security_review.errors import ConfigurationError, LLMError
from security_review.preflight import probe_provider, validate_pricing


def test_validate_pricing_passes_on_shipped_config():
    cfg = load_config(None)
    validate_pricing(cfg)  # must not raise


def test_validate_pricing_raises_for_unpriced_model():
    cfg = load_config(None)
    cfg = cfg.model_copy(update={
        "llm": cfg.llm.model_copy(update={"provider_model": "copilot:not-a-model"}),
    })
    with pytest.raises(ConfigurationError):
        validate_pricing(cfg)


async def test_probe_provider_records_cost_with_test_model(monkeypatch: pytest.MonkeyPatch):
    cfg = load_config(None)
    monkeypatch.setattr("security_review.preflight.build_model", lambda *a, **k: TestModel())
    cost_tracker = CostTracker()

    await probe_provider(cfg, cost_tracker)

    log = cost_tracker.to_audit_log()
    assert len(log) == 1
    assert log[0]["agent"] == "preflight"


async def test_probe_provider_raises_llm_error_on_failure(monkeypatch: pytest.MonkeyPatch):
    cfg = load_config(None)

    def _raise(messages, info):
        raise RuntimeError("401 unauthorized")

    monkeypatch.setattr(
        "security_review.preflight.build_model", lambda *a, **k: FunctionModel(_raise),
    )
    cost_tracker = CostTracker()

    with pytest.raises(LLMError) as exc_info:
        await probe_provider(cfg, cost_tracker)

    assert exc_info.value.code == "LLM_AUTH_FAILED"
    assert cost_tracker.to_audit_log() == []  # failed probe records no cost
