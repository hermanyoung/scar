# Changelog

## Unreleased
- Adversarial verification & pipeline resilience (plan 020, Phases 1-3):
  - **Pass 6 "verify"** (full mode is now 7 passes; merge is Pass 7): every
    holistic finding (config-review findings opt-in) gets an independent
    verdict from a separate skeptic agent that sees only the claim + freshly
    re-read source — never the finder's reasoning — and defaults to
    FALSE_POSITIVE. New required `verification` config section
    (`enabled`/`model`/`samples`/`verify_holistic`/`verify_config_review`).
    Semantic change: verify verdicts flow into the same
    `properties.triage_verdict` field triage uses, so "Triage" counts in
    summary/terminal reports now include Pass-6 verdicts. The merge
    auto-CONFIRMED default for verdict-less `SR-*` findings only applies when
    verification is disabled; with it enabled, unadjudicated findings are
    NEEDS_CONTEXT. Refuted findings are kept (scored low), never dropped.
  - **Checkpoint/resume**: each completed pass is checkpointed atomically to
    `var/output/{run}/state/`; `review --resume <run-dir>` restores completed
    passes and prior spend, re-runs preflight, and honours `--fail-on` exit
    codes. Corrupt checkpoints fail fast (ConfigurationError), never silently
    recompute. `--stream` writes `security-report.partial.sarif` after each
    LLM pass.
  - **Uniform transport retry**: `RetryingModel` wraps all five providers,
    activating `providers.<name>.backoff_seconds` (previously copilot-only)
    with bounded exponential backoff on non-fatal transport errors and on
    empty responses (previously returned as success and lost at parse time).
    Fatal (auth/config) and context-overflow errors are never retried.
  - Shared `run_in_batches` driver extracted from triage/holistic (verify
    reuses it — no third hand-rolled batch loop).
- Operational readiness remediation (plan 018): degradation ledger, salvage merge,
  run-scoped tmp, LLM preflight, --fail-on exit codes, truthful LLM coverage.
- Invariant debt remediation (plan 019): CWE integrity (deterministic stamp, hadolint mapping, CWE-829), pre-merge URI dedup fix, overflow halve-and-retry, CopilotModel required params, backlog status reconciliation.

## 1.0.0 — 2026-05-22
- Initial public release.
