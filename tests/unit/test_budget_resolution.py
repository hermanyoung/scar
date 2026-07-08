"""Tests for canonical pricing-key resolution in CostTracker (Plan 018 WP4)."""
from __future__ import annotations

import pytest

from security_review.budget import CostTracker, ModelPricing, pricing_entry_exists
from security_review.errors import ConfigurationError


def test_record_resolves_alias_to_wire_form():
    tracker = CostTracker(pricing={
        "copilot:claude-opus-4.6": ModelPricing(input_per_token=0.000005, output_per_token=0.000025),
    })
    entry = tracker.record(
        agent_name="triage", batch_id="b-000",
        model_requested="copilot:claude-opus",
        tokens_in=100, tokens_out=50,
    )
    assert entry.model_responded == "copilot:claude-opus-4.6"
    assert entry.model_requested == "copilot:claude-opus"
    assert entry.cost_usd > 0


def test_record_unknown_model_raises_with_both_strings_in_message():
    tracker = CostTracker(pricing={})
    with pytest.raises(ConfigurationError) as exc_info:
        tracker.record(
            agent_name="triage", batch_id="b-000",
            model_requested="copilot:not-a-model",
            tokens_in=10, tokens_out=10,
        )
    message = str(exc_info.value)
    assert "copilot:not-a-model" in message
    assert "copilot:not-a-model" in message  # resolved form is identical here (no alias match)


def test_pricing_entry_exists_resolves_alias_and_provider_override():
    # "claude-opus" -> alias "claude-opus-4.6" -> anthropic override "claude-opus-4-6"
    assert pricing_entry_exists("anthropic:claude-opus") is True


def test_pricing_entry_exists_false_for_unknown_model():
    assert pricing_entry_exists("copilot:definitely-not-a-real-model") is False


def test_pricing_entry_exists_false_for_missing_model_part():
    assert pricing_entry_exists("copilot") is False


@pytest.mark.parametrize("model_string", [
    "copilot:claude-opus-4.6",
    "copilot:claude-sonnet-4.6",
    "anthropic:claude-sonnet",
    "openai:gpt",
])
def test_readme_provider_examples_resolve_to_pricing_entries(model_string):
    assert pricing_entry_exists(model_string) is True
