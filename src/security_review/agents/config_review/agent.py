"""Pass 5: PydanticAI configuration review agent.

All context is pre-materialized in the prompt (P14). No tool calls.
Reviews appsettings, launchSettings, Dockerfile, CI YAML,
pyproject.toml, .env patterns for security issues.
"""
from __future__ import annotations

from pydantic_ai import Agent

from security_review.agents.deps import SecurityReviewDeps, register_prompt_loader


def build_config_review_agent(output_retries: int) -> Agent:
    """Construct the config review agent with the configured output-parsing retry budget.

    output_retries is constructor-only in the installed pydantic-ai version
    (Agent.run() does not accept a retries= kwarg), so the agent is built
    fresh per call from llm.output_retries instead of as a fixed module-level
    singleton — Agent() construction is ~6us, negligible next to the LLM call.
    """
    agent = Agent(
        output_type=str,
        system_prompt=(
            "You are a security engineer reviewing configuration files for security "
            "misconfigurations. The file contents are provided directly in the prompt "
            "— do NOT call any tools."
        ),
        deps_type=SecurityReviewDeps,
        output_retries=output_retries,
    )
    register_prompt_loader(agent, "config_review")
    return agent
