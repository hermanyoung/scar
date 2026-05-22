# ADR-003: Inline Context Over Tool Calls

**Status:** Accepted
**Date:** 2026-05-05
**Context:** Copilot SDK reliability, provider portability

## Decision

All LLM context (file contents, SAST findings, metadata) is read locally and inlined in the prompt before the LLM call. Agents have zero tools registered. No `read_file` tool calls through provider SDKs.

This implements Principle P14 (All LLM Context Is Pre-Materialized Locally).

## Context

The original architecture used PydanticAI tool calls for file reading — the holistic agent would call `read_file(path)` through the provider SDK to fetch file contents during analysis. This failed catastrophically on the Copilot SDK:

- Tool calls through Copilot route as JSON-RPC → CLI subprocess → GitHub API → LLM → back. Each round-trip takes 5-15s.
- Copilot's 429 rate limits surface as silent `asyncio.TimeoutError`, not HTTP 429 responses. Tools time out without explanation.
- A single holistic CWE check requiring 5 file reads would take 60-90s and frequently fail mid-way, producing partial results (e.g., IDOR findings missing because the service layer file was never read).
- Multi-file reasoning requires all related files in the same context. Sequential tool calls meant the LLM saw files one at a time, losing cross-file patterns.

File reading is a local operation (microseconds). Delegating it to a remote LLM tool call that routes through a provider SDK is architecturally wrong.

## Consequences

- `context_builder.py` reads files locally and builds prompt content with token budgeting
- Files are sorted by `security_weight` and truncated if exceeding the token budget
- Each agent call is a single LLM request — no multi-turn, no tool calls, no timeouts
- `agents/` modules register zero tools: `rg "\.tool\(" src/security_review/agents/` returns zero results
- Adding a new pass means: use `context_builder` to build context → call agent → parse output
- Cross-file reasoning works because all related files are in the same prompt
- Token budget is the constraint — very large codebases may need file selection strategies

## References

- `docs/06-plans/007-pre-materialized-context.md` — implementation plan
- `src/security_review/context_builder.py` — file reading and token budgeting
- Principle P14 in `docs/03-principles/01-project-principles.md`
