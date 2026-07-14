"""Pass 6: PydanticAI independent adversarial verification agent.

A SEPARATE agent from holistic/triage. It sees only the claim (CWE,
location) and freshly re-read source — never the finder's rationale,
evidence, confidence, or remediation (those are persuasion, not evidence,
and cause anchoring). It defaults to disbelief.

All context is pre-materialized in the prompt (P14). Zero tools.
Output: plain text. The pass code parses it via output_parser
(reuses Pass 3's TriagedFinding / parse_triage_response machinery).
"""
from __future__ import annotations

from pydantic_ai import Agent

from security_review.agents.deps import SecurityReviewDeps, register_prompt_loader


def build_verify_agent(output_retries: int) -> Agent:
    """Construct the verify agent with the configured output-parsing retry budget.

    output_retries is constructor-only in the installed pydantic-ai version
    (Agent.run() does not accept a retries= kwarg), so the agent is built
    fresh per call from llm.output_retries instead of as a fixed module-level
    singleton — Agent() construction is ~6us, negligible next to the LLM call.
    """
    agent = Agent(
        output_type=str,
        system_prompt=(
            "You are an independent security reviewer auditing a claimed vulnerability "
            "found by another tool. You did NOT find it and have no stake in it. "
            "The source code is provided directly in the prompt — do NOT call any tools.\n\n"
            "State your verdict clearly:\n"
            "- **Verdict:** CONFIRMED | FALSE_POSITIVE | NEEDS_CONTEXT\n"
            "- **Confidence:** 0.0 to 1.0\n"
            "- **Rationale:** cite the specific line(s) that support your verdict"
        ),
        deps_type=SecurityReviewDeps,
        output_retries=output_retries,
    )
    register_prompt_loader(agent, "verify")
    return agent
