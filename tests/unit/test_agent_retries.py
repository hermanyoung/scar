"""Tests that llm.output_retries actually reaches the constructed Agent.

Agent.run() in the installed pydantic-ai version does not accept a retries=
kwarg -- output_retries is constructor-only -- so each pass now builds its
agent fresh from state.config.llm.output_retries instead of importing a
fixed module-level singleton. These tests confirm the value is actually
wired through, not silently dropped again.
"""
from __future__ import annotations

from security_review.agents.config_review.agent import build_config_review_agent
from security_review.agents.holistic.agent import build_holistic_agent
from security_review.agents.triage.agent import build_triage_agent


def test_build_triage_agent_wires_output_retries():
    agent = build_triage_agent(5)
    assert agent._max_result_retries == 5


def test_build_holistic_agent_wires_output_retries():
    agent = build_holistic_agent(2)
    assert agent._max_result_retries == 2


def test_build_config_review_agent_wires_output_retries():
    agent = build_config_review_agent(4)
    assert agent._max_result_retries == 4
