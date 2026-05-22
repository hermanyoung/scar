# Provider and Model Architecture

## Overview

SCAR supports 5 LLM providers, each with a PydanticAI `Model` adapter. All providers are routed through a single factory in `model_providers.py` and resolved via `config/models.yaml` aliases.

## Providers

| Provider | SDK | Auth | Cost | Model adapter |
|----------|-----|------|------|---------------|
| `copilot:` | `github-copilot-sdk` 0.2.2 | GitHub OAuth | $0 (subscription) | `copilot_model.py` |
| `claude:` | `claude-agent-sdk` | Claude Max/Pro OAuth | $0 (subscription) | `claude_model.py` |
| `anthropic:` | `pydantic-ai[anthropic]` | `ANTHROPIC_API_KEY` | Per-token | PydanticAI built-in |
| `openai:` | `pydantic-ai[openai]` | `OPENAI_API_KEY` | Per-token | PydanticAI built-in |
| `codex:` | `codex-app-server` | ChatGPT Plus | $0 (subscription) | `codex_model.py` |

**Default provider:** `copilot:claude-opus` (set in `config/settings/security_review.yaml`).

## Model Resolution

Model aliases are defined in `config/models.yaml`:

```
--provider copilot:claude-opus
  1. "claude-opus" → aliases → "claude-opus-4.6"     (canonical ID)
  2. "copilot" → providers.copilot → no override      (use canonical)
  3. Wire ID: "claude-opus-4.6"

--provider anthropic:claude-opus
  1. "claude-opus" → aliases → "claude-opus-4.6"     (canonical ID)
  2. "anthropic" → providers.anthropic → override      (dots → dashes)
  3. Wire ID: "claude-opus-4-6"
```

Copilot uses dots (`claude-opus-4.6`). Anthropic/Claude use dashes (`claude-opus-4-6`).

## Output Routing

Providers split into two output paths based on `model_capabilities.supports_native_json()`:

| Path | Providers | output_type | Parsing |
|------|-----------|-------------|---------|
| Native JSON | `anthropic:`, `openai:` | `HolisticReviewResult` | Schema-validated by PydanticAI |
| Prompted markdown | `copilot:`, `claude:`, `codex:` | `str` | `output_parser.py` (JSON-first, markdown fallback) |

See ADR-004 and ADR-006 for the rationale behind this split.

## Model Settings

`model_settings.py` builds provider-specific `ModelSettings`:

| Setting | anthropic | copilot/claude/codex | openai |
|---------|-----------|---------------------|--------|
| Temperature | Respected (0.2 default) | **Ignored** — hardcoded 0.1 in runtime (ADR-002) | Respected |
| Prompt caching | `anthropic_cache_instructions` | N/A | N/A |
| Extended thinking | `anthropic_thinking: adaptive` | N/A | N/A |
| Reasoning effort | N/A | Available but unused | N/A |

## Provider Factory

`model_providers.py` contains one factory function per provider. Each returns a PydanticAI `Model` instance:

- `get_copilot_provider()` → `CopilotModel` (wrapped in `ConcurrencyLimitedModel`)
- `get_claude_provider()` → `ClaudeModel`
- `get_anthropic_provider()` → PydanticAI `AnthropicModel`
- `get_openai_provider()` → PydanticAI `OpenAIModel`
- `get_codex_provider()` → `CodexModel`

`providers.py:build_model()` dispatches to the correct factory based on the provider prefix.

## Benchmark Results (2026-05-11)

Against the `example-target` reference target, 11 baseline CWEs:

| Provider | Score | Notes |
|----------|-------|-------|
| `claude:claude-opus` | **11/11** | Gold standard |
| `anthropic:claude-opus` | **10/11** | CWE-863 intermittent consolidation |
| `copilot:claude-opus` | **9/11** | CWE-116/522 variance (not systematic) |
| `codex:gpt` | **9/11** | CWE-522 GPT limitation |
| `openai:gpt` | N/A | Requires API key (not tested) |
