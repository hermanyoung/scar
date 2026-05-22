# ADR-005: One CWE Per Agent Call

**Status:** Accepted
**Date:** 2026-05-03
**Context:** Detection accuracy, measurable recall

## Decision

Each CWE in the holistic pass gets its own LLM call with a focused prompt. The orchestrator runs one agent call per CWE, not one call per file batch or one monolithic call for all CWEs.

This implements Principle P12 (Accuracy Over Volume — One CWE, One Agent, One Focused Question).

## Context

Early prototypes used a monolithic holistic prompt: "Review these files for authorization issues, crypto problems, SSRF, deserialization, information disclosure, and business logic flaws." This produced:

- **Shallow reasoning:** the model would mention 15 CWEs superficially rather than deeply analyzing any single one
- **Missed findings:** IDOR (CWE-863) was consistently missed when competing with crypto (CWE-327) and info disclosure (CWE-200) for attention
- **Unmeasurable quality:** when the prompt covers 20 CWEs, you can't benchmark recall per CWE — you only know "it found 5 things"
- **Unfixable prompts:** when CWE-863 detection was poor, improving the IDOR section risked degrading other CWE detection

Splitting to one-CWE-per-call solved all four problems:

- **Deep reasoning:** the model spends its full context window and reasoning on one vulnerability class
- **Higher recall:** CWE-863 improved from 1 finding (monolithic) to 3-4 findings (focused) against the example-target baseline
- **Measurable:** `scripts/benchmark_cwes.py` tests each CWE independently — regression is per-CWE, not per-pipeline
- **Fixable:** when CWE-209 was failing on 3/4 providers, we improved one prompt section and re-tested one CWE

## Consequences

- `taxonomy/cwe.yaml` defines the CWE registry — each entry may have a `holistic_check: true` flag
- The holistic pass runs N sequential LLM calls (one per CWE with `holistic_check: true`)
- Progress shows per-CWE: `[3/25] CWE-862 Missing Authorization... 2 findings`
- `context_builder.py` selects files relevant to each CWE (e.g., controllers for CWE-863, config files for CWE-312)
- Cost scales linearly with CWE count — 25 CWEs × ~$0.15/call = ~$3.75 for the holistic pass
- CWEs can be grouped in future if cost is a concern, but only with A/B evidence that grouping doesn't degrade recall

## References

- Principle P12 in `docs/03-principles/01-project-principles.md`
- `src/security_review/passes/holistic.py` — per-CWE orchestration
- `scripts/benchmark_cwes.py` — per-CWE benchmarking
