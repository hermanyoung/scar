"""Pass 5: PydanticAI configuration review agent.

All context is pre-materialized in the prompt (P14). No tool calls.
Reviews appsettings, launchSettings, Dockerfile, CI YAML,
pyproject.toml, .env patterns for security issues.
"""
from __future__ import annotations

from pydantic_ai import Agent, RunContext

from security_review.agents.deps import SecurityReviewDeps, load_prompt

config_review_agent = Agent(
    output_type=str,
    system_prompt=(
        "You are a security engineer reviewing configuration files for security "
        "misconfigurations. The file contents are provided directly in the prompt "
        "— do NOT call any tools."
    ),
    deps_type=SecurityReviewDeps,
)


@config_review_agent.system_prompt
async def config_review_system_prompt(ctx: RunContext[SecurityReviewDeps]) -> str:
    return load_prompt("config_review")
