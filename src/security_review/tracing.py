"""Per-agent trace file writer for --trace mode.

Writes one JSON file per agent call to var/output/{run}/traces/.
Each file contains the full PydanticAI message history: system prompt,
user prompt, tool calls, tool responses, and structured output.

Traces are for post-hoc debugging — they answer "what did the LLM see
and say?" without bloating operational logs.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import structlog
from pydantic_ai import AgentRunResult

from security_review.fsio import atomic_write_json

logger = structlog.get_logger()


def write_trace(
    *,
    output_dir: Path,
    agent_name: str,
    trace_id: str,
    prompt: str,
    result: AgentRunResult[Any],
    output: dict | None = None,
) -> None:
    """Write a single agent trace to disk.

    Args:
        output_dir: Run output directory (var/output/{date}-{target}-{run}/).
        agent_name: Agent name (triage, holistic, config_review).
        trace_id: Unique ID for this call (e.g. "triage-003", "cwe-862").
        prompt: The user prompt sent to the agent.
        result: PydanticAI AgentRunResult with .all_messages_json() and .usage().
        output: Optional structured output dict to include.
    """
    traces_dir = output_dir / "traces"
    traces_dir.mkdir(parents=True, exist_ok=True)

    usage = result.usage()
    trace = {
        "agent": agent_name,
        "trace_id": trace_id,
        "prompt": prompt,
        "messages": json.loads(result.all_messages_json()),
        "usage": {
            "request_tokens": usage.request_tokens,
            "response_tokens": usage.response_tokens,
            "total_tokens": usage.total_tokens,
        },
    }

    if output is not None:
        trace["output"] = output

    trace_path = traces_dir / f"{trace_id}.json"
    atomic_write_json(trace_path, trace)

    logger.debug("trace.written", agent=agent_name, trace_id=trace_id, path=str(trace_path))
