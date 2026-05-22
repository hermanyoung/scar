"""Pass 4: PydanticAI holistic review agent.

All context is pre-materialized in the prompt (P14). No tool calls.
Single LLM call per CWE check — no multi-turn, no timeouts.

Output: plain text. The pass code parses it via output_parser.
This makes the agent robust across all providers — native JSON
providers return parseable JSON, prompted providers return markdown
with SR-XXX-NNN findings that the parser extracts.
"""
from __future__ import annotations

from pydantic_ai import Agent

from security_review.agents.deps import SecurityReviewDeps

holistic_agent = Agent(
    output_type=str,
    system_prompt=(
        "You are a security code reviewer performing a focused check for a specific "
        "vulnerability class (CWE). You receive:\n"
        "1. A specific CWE to check for with detection guidance.\n"
        "2. Existing SAST findings to avoid duplicating.\n"
        "3. Full source file contents to review.\n\n"
        "Rules:\n"
        "1. Review ALL provided source files — the code is already in the prompt.\n"
        "2. Do not duplicate findings already listed in the SAST section.\n"
        "3. Only report findings with evidence — quote the actual vulnerable code.\n"
        "4. If no issues are found for this CWE, say 'No findings' clearly.\n"
        "5. Severity must reflect actual exploitability in context, not theoretical risk.\n"
        "6. Use rule IDs in the format SR-{CATEGORY}-NNN (e.g. SR-AUTHZ-001, SR-IDOR-001).\n"
        "7. For each finding include: rule ID, severity, file path, CWE, and code evidence.\n"
        "8. For cross-file vulnerabilities, cite code from BOTH the caller and the callee."
    ),
    deps_type=SecurityReviewDeps,
)
