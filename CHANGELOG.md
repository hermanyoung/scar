# Changelog

## Unreleased
- Review integrity & self-compliance (plan 021):
  - **WP-A** — an empty/whitespace-only holistic LLM response is now classified
    `parse_failed` (retried, then a `check_failed` degradation on exhaustion)
    instead of silently counting as a clean "no findings" check.
  - **WP-B** — holistic finding file paths are validated against the files
    actually included in the prompt (exact match, then suffix/basename
    fallback); unresolvable paths omit `locations` from the SARIF result and
    set `properties.location_unresolved: true` instead of fabricating a
    location, plus a `location_unresolved` degradation.
  - **WP-C** — call-graph build failures now surface as an operator-visible
    `call_graph_failed` degradation (previously a silent log line); the code
    quality summary failing after a review run now also prints to stderr, not
    just the log.
  - **WP-D** — the call-graph/fingerprint SQLite cache moved out of the
    scanned repository into SCAR's own `var/cache/graphs/<target-key>/`; SCAR
    no longer creates a `.scar/` directory in any target it reviews. Old
    `.scar/` directories in previously scanned targets are orphaned and safe
    to delete manually.
  - **WP-E** — `code_quality`'s Bandit/Radon tool runs now use the exact same
    exclude set as the AST-based scoring dimensions, so a file measured by
    one is never silently skipped by the other.
  - **WP-F** — consolidated on a single PQI implementation: the pre-commit
    hook now calls `python scar.py quality` instead of the standalone
    `scripts/code_quality.py`, which is deleted.
  - **WP-G** — `setup.py`'s auto-fix path runs commands without `shell=True`;
    fix commands that are genuinely shell scripts (exports, multi-step
    instructions) are now surfaced as manual steps instead of being executed
    unsafely.
  - **WP-H** — the subprocess-isolation and init-minimal rule checks now cover
    all of `src/` (previously `security_review/`-only), closing the gap that
    let `code_quality/tools.py` call `subprocess.run` directly and
    `code_analysis/__init__.py` carry a full `analyze()` implementation; both
    are now routed/split accordingly. Remaining deliberately-scoped rules are
    documented with their reasons.
  - **WP-I** — `pydantic-ai` pinned to the exact tested version (`==1.63.0`,
    was a floating `>=0.2.14`); deprecated `usage.request_tokens`/
    `response_tokens` and `OpenAIModel` APIs migrated to their replacements.
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
