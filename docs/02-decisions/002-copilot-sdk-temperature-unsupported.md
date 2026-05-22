# ADR-002: Copilot SDK Does Not Support Temperature

**Status:** Accepted
**Date:** 2026-05-11
**Context:** Provider parity, benchmark variance

## Decision

Accept that the Copilot SDK ignores our `temperature` setting. Do not attempt to forward `model_settings.temperature` to the SDK. Document the limitation and use multi-run averaging for benchmarks.

## Context

Investigation of `github-copilot-sdk` 0.2.2 and 0.3.0 source confirmed:

- `SessionConfig` has no `temperature`, `top_p`, `seed`, or `model_parameters` field
- `send_and_wait()` accepts only `prompt`, `attachments`, `mode`, `timeout`
- The Copilot agent runtime hardcodes `temperature=0.1` server-side (GitHub issue #932)
- The only model-behaviour knob exposed is `reasoning_effort` (low/medium/high/xhigh)

Our `model_settings.py` builds `ModelSettings(temperature=0.2)` for all non-anthropic providers, including copilot. PydanticAI passes this to `CopilotModel.request()`, but `copilot_model.py:_execute_request()` never forwards it to the SDK session — it is silently dropped.

Benchmark comparison at temperature 0.1 vs 0.2 on `anthropic:claude-opus` showed identical results (10/11 both), confirming the 0.1-0.2 range has negligible impact on detection quality.

## Consequences

- `copilot_model.py` does not forward temperature to the SDK (no code change needed — it already doesn't)
- Copilot runs at the runtime's hardcoded 0.1 regardless of our config
- Benchmark variance on copilot (CWE-116/522 intermittent) is expected and addressed via `--runs 3`
- If issue #932 is resolved and the SDK adds a temperature parameter, update `_execute_request` to forward `model_settings.temperature`
- `reasoning_effort` could be forwarded in future if needed (only works on models with `capabilities.supports.reasoning_effort == True`)

## References

- GitHub issue: `github/copilot-sdk#932` ("Reasoning effort and Temperature values wrong for Opus")
- `src/security_review/copilot_model.py` — adapter implementation
- `src/security_review/model_settings.py` — where temperature is set
