"""Pass 3: PydanticAI triage agent.

All context is pre-materialized in the prompt (P14). No tool calls.
Single LLM call per finding — no multi-turn, no timeouts.

Output: plain text. The pass code parses it via output_parser.
This makes the agent robust across all providers — native JSON
providers return parseable JSON, prompted providers return markdown.
"""
from __future__ import annotations

from pydantic_ai import Agent, RunContext

from security_review.agents.deps import SecurityReviewDeps, load_prompt

triage_agent = Agent(
    output_type=str,
    system_prompt=(
        "You are a security code reviewer performing triage on static analysis findings. "
        "The source code is provided directly in the prompt — do NOT call any tools.\n\n"
        "For each finding, state your verdict clearly:\n"
        "- **Verdict:** CONFIRMED | FALSE_POSITIVE | NEEDS_CONTEXT\n"
        "- **Confidence:** 0.0 to 1.0\n"
        "- **Rationale:** explain WHY in 1-3 sentences"
    ),
    deps_type=SecurityReviewDeps,
)


@triage_agent.system_prompt
async def triage_system_prompt(ctx: RunContext[SecurityReviewDeps]) -> str:
    return load_prompt("triage")
