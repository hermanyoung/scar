"""Pass 4: Holistic cross-file security review agent.

Two modes:
- inline (default): pre-materialized context, no tool calls, single LLM request
- tools: tool-call based, LLM reads files via read_file/get_sast_findings
"""
