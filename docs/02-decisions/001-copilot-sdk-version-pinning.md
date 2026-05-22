# ADR-001: Copilot SDK Pinned to 0.2.2

**Status:** Accepted
**Date:** 2026-05-08
**Context:** Provider reliability, benchmark regression

## Decision

Pin `github-copilot-sdk` to version 0.2.2 in `requirements.txt` and `pyproject.toml`. Do not upgrade to 0.3.0 or later without A/B benchmark verification.

## Context

The Copilot SDK is the default provider (`copilot:claude-opus` in `config/settings/security_review.yaml`). Version 0.3.0 was released with breaking API changes and a confirmed detection regression.

A/B testing (3 runs each, CWE-312 and CWE-522) showed:
- **0.2.2:** 9/9 pass (100%)
- **0.3.0:** 3/9 pass (33%)

0.3.0 responses complete in 10-20s vs 60-160s on 0.2.2 — suspected prompt truncation causes the model to miss findings.

0.3.0 also introduces breaking changes:
- Permission handler return value: `"approved"` → `"approve-once"`
- MCP server config renames
- `*Params` → `*Request` type renames (39 types)

## Consequences

- `requirements.txt` specifies `github-copilot-sdk==0.2.2` (exact pin)
- Before any SDK upgrade, run: `python scripts/benchmark_cwes.py --ab-sdk 0.2.2,<new> --runs 3 --providers copilot:claude-opus`
- The A/B test must show no regression on CWE-312 and CWE-522 specifically (these are the canary CWEs)
- `copilot_model.py` uses the 0.2.2 API surface (`on_permission_request` returns `True`, not `"approve-once"`)

## References

- `scripts/benchmark_cwes.py --ab-sdk` for A/B testing
- AGENTS.md "SDK Version Pinning" section
