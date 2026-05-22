# ADR-006: Native JSON Schema for API Providers Only

**Status:** Accepted
**Date:** 2026-05-08
**Context:** Provider-specific output routing, finding consolidation

## Decision

Use `output_type=HolisticReviewResult` (native JSON schema enforcement) only for providers that support it at the API level: `anthropic` and `openai`. All other providers (`copilot`, `claude`, `codex`) use `output_type=str` with markdown format instructions.

This is a refinement of ADR-004 — not all providers must use plain text. Providers with native JSON support get validated structured output; prompted providers get markdown parsing.

## Context

After switching all agents to `output_type=str` (ADR-004), native JSON providers (anthropic, openai) were producing markdown that had to be parsed with regex — losing the validation and reliability that native JSON schema provides.

Re-enabling `output_type=HolisticReviewResult` for anthropic revealed a new problem: **finding consolidation**. With JSON schema enforcement, the model tends to consolidate related findings into fewer items. For CWE-863 (IDOR), instead of 3 separate findings (GetContact, UpdateContact, DeleteContact), anthropic returned 1 combined finding ("Contacts Retrieved, Updated, and Deleted Without Ownership Check").

The fix was a **granularity instruction** added to all holistic prompts:

> "Create a separate finding for each distinct vulnerable call site — do not consolidate multiple endpoints or methods into one finding."

With this instruction, native JSON providers produce granular findings while still benefiting from schema validation.

## Consequences

- `model_capabilities.py:supports_native_json()` returns `True` for `anthropic:` and `openai:` providers
- `passes/holistic.py` checks `supports_native_json()` to choose `output_type`
- Native JSON providers: `output_type=HolisticReviewResult` — validated, no parsing needed
- Prompted providers: `output_type=str` — markdown format instructions, parsed by `output_parser.py`
- All holistic prompts include the granularity instruction to prevent consolidation on native JSON providers
- `output_parser.py` JSON-first path handles native JSON; markdown-fallback handles prompted providers
- Temperature has negligible effect on consolidation (tested 0.1 vs 0.2 — identical results)

## References

- ADR-004 (Agents Return Plain Text) — the base decision this refines
- `src/security_review/model_capabilities.py` — `supports_native_json()` routing
- `config/prompts/holistic/csharp.md` — granularity instruction in Output section
