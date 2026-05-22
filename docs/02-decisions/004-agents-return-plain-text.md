# ADR-004: Agents Return output_type=str

**Status:** Accepted
**Date:** 2026-05-07
**Context:** Provider compatibility, structured output reliability

## Decision

All PydanticAI agents use `output_type=str`. Structured data is extracted from plain text responses by `output_parser.py` (JSON-first, markdown fallback). Native JSON schema enforcement (`output_type=SomePydanticModel`) is used only for providers that support it natively (anthropic, openai) — see ADR-006.

This implements AGENTS.md Rule #7: "Agents return output_type=str."

## Context

PydanticAI supports two structured output modes:
- **Native JSON schema** (`json_schema`): provider enforces the schema at the API level. Available on Anthropic and OpenAI.
- **Prompted** (`prompted`): PydanticAI injects the schema as text in the system prompt and validates the response. The LLM must produce valid JSON matching the schema.

The prompted mode failed on Copilot and Claude SDK providers:
- The schema injection adds ~500-1000 tokens to the system prompt
- The LLM frequently returned responses that were valid security analysis but invalid JSON (missing commas, unescaped quotes in evidence code blocks, truncated closing braces)
- PydanticAI's validation retry consumed 3-4 additional LLM calls per failure, wasting ~800s per pipeline run
- The retry often produced worse output (the model would simplify its analysis to fit the schema)

Switching to `output_type=str` with format instructions and a parser eliminated all retries:
- The LLM returns natural markdown with structured headers (`### SR-IDOR-001`, `**Severity:** HIGH`, `**File:** path`)
- `output_parser.py` extracts findings with regex (JSON-first for native providers, markdown fallback for prompted)
- Zero retry waste — every LLM call produces usable output

## Consequences

- All agents in `src/security_review/agents/` use `output_type=str`
- `output_parser.py` handles two response formats: JSON (from native providers) and markdown (from prompted providers)
- Format instructions are injected by `model_capabilities.py` based on `supports_native_json()`
- Markdown parsing handles multiple LLM response formats: `### SR-XXX-NNN`, `### Finding N` tables, bold-colon (`**File:** path`), table cells (`| File | path |`)
- Adding a new output field means updating both the JSON schema (for native providers) and the markdown regex (for prompted providers)

## References

- `src/security_review/output_parser.py` — JSON-first/markdown-fallback parser
- `src/security_review/model_capabilities.py` — format instruction routing
- AGENTS.md Rule #7
