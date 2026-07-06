"""Pipeline orchestrator: run_pipeline().

The pipeline is linear — no pass runs concurrently with another.
Within a pass, tools/batches may run concurrently.
"""
from __future__ import annotations

import time
from collections.abc import Awaitable, Callable

import structlog

from security_review.errors import is_fatal_error
from security_review.models.degradation import Degradation
from security_review.passes.state import PassError, PipelineState, ProgressCallback

logger = structlog.get_logger()


def _safe_progress(callback: ProgressCallback, pass_number: int, pass_name: str, status: str, detail: str) -> None:
    """Call progress callback, swallowing any exceptions."""
    try:
        callback(pass_number, pass_name, status, detail)
    except Exception as e:
        logger.debug("progress.callback_failed", error=str(e))


# Re-export so existing imports from pipeline still work
__all__ = ["PipelineState", "ProgressCallback", "run_pipeline"]


async def _run_pass(
    state: PipelineState,
    progress: ProgressCallback,
    pass_number: int,
    pass_name: str,
    run_fn: Callable[[PipelineState], Awaitable[None]],
) -> bool:
    """Run one pass, isolating any exception that escapes it.

    Each pass already isolates its own per-item/per-batch failures
    internally (triage.py, holistic.py, config_review.py use
    is_fatal_error() at that granularity). An exception reaching here means
    the entire pass failed outright — record it on state.errors and report
    it via progress("failed", ...) instead of letting it propagate and
    silently discard every result from passes that already succeeded.

    Also recorded as a Degradation (kind="pass_failed"): a whole-pass
    failure is the most severe form of coverage loss, so it must flip
    executionSuccessful to False in the SARIF invocation and be visible
    to --fail-on-degraded, exactly like any narrower in-pass degradation.

    Returns True if the pass completed, False if it failed (callers should
    stop attempting subsequent passes, since they typically depend on this
    pass's output, but must still proceed to the merge step).
    """
    try:
        await run_fn(state)
        return True
    except Exception as e:
        fatal = is_fatal_error(e)
        logger.error(
            "pipeline.pass_failed",
            pass_name=pass_name,
            error=str(e),
            error_type=type(e).__name__,
            fatal=fatal,
        )
        state.errors.append(PassError(
            pass_name=pass_name,
            error=str(e),
            error_type=type(e).__name__,
            fatal=fatal,
        ))
        state.degrade(Degradation(
            pass_name=pass_name, kind="pass_failed", subject=pass_name,
            detail=f"pass '{pass_name}' failed outright ({type(e).__name__}: {e}) — "
                   f"subsequent passes were skipped",
        ))
        progress(pass_number, pass_name, "failed", f"{type(e).__name__}: {e}")
        return False


async def run_pipeline(state: PipelineState) -> "Path":
    """Execute the 5-pass pipeline. Returns path to final SARIF.

    If a pass fails outright, remaining passes are skipped (they generally
    depend on earlier state) but the pipeline still proceeds to merge, so
    whatever completed before the failure is written to a report instead of
    being silently discarded. Failures are recorded on state.errors and
    surfaced in the report (Principle P6 — partial failures must be visible).
    """
    from security_review.passes.config_review import run_config_review
    from security_review.passes.holistic import run_holistic
    from security_review.passes.inventory import run_inventory
    from security_review.passes.merge import run_merge
    from security_review.passes.sast import run_sast
    from security_review.passes.triage import run_triage

    structlog.contextvars.bind_contextvars(
        run_id=state.run_id,
        target=str(state.target_path),
        mode=state.config.review.mode,
    )
    logger.info("pipeline.started")
    start = time.monotonic()
    mode = state.config.review.mode

    # Wrap the progress callback so any exception in it cannot crash the pipeline.
    # This protects both pipeline.py's own calls AND sub-pass calls via state.on_progress.
    raw_progress = state.on_progress
    def progress(pass_number: int, pass_name: str, status: str, detail: str) -> None:
        _safe_progress(raw_progress, pass_number, pass_name, status, detail)
    state.on_progress = progress

    # Determine total passes for this mode
    if mode == "full":
        total_passes = 6
    elif mode == "sast-triage":
        total_passes = 4
    else:
        total_passes = 3

    # Pass 1: Inventory
    progress(1, "inventory", "running", "Discovering files...")
    if await _run_pass(state, progress, 1, "inventory", run_inventory):
        file_count = state.manifest.total_files if state.manifest else 0
        langs = state.manifest.languages if state.manifest else {}
        lang_str = ", ".join(f"{v} {k}" for k, v in sorted(langs.items(), key=lambda x: -x[1]) if v > 0)
        progress(1, "inventory", "done", f"{file_count} files ({lang_str})")
    else:
        return await _merge_and_finish(state, progress, total_passes, start)

    # Pass 2: SAST
    progress(2, "sast", "running", "Running SAST tools...")
    if await _run_pass(state, progress, 2, "sast", run_sast):
        sast_count = sum(
            len(run.get("results", []))
            for run in (state.sast_sarif or {}).get("runs", [])
        )
        progress(2, "sast", "done", f"{sast_count} findings")
    else:
        return await _merge_and_finish(state, progress, total_passes, start)

    if mode == "full":
        # Pass 3: Triage
        progress(3, "triage", "running", "LLM triaging SAST findings...")
        if not await _run_pass(state, progress, 3, "triage", run_triage):
            return await _merge_and_finish(state, progress, total_passes, start)
        if state.triage_result:
            t = state.triage_result
            progress(3, "triage", "done",
                     f"{t.total_confirmed} confirmed, {t.total_false_positive} FP, "
                     f"{t.total_needs_context} needs context")
        elif any(d.pass_name == "triage" for d in state.degradations):
            progress(3, "triage", "done", "0 triaged — see coverage gaps")
        else:
            progress(3, "triage", "done", "skipped (no findings to triage)")

        # Pass 4: Holistic
        progress(4, "holistic", "running", "LLM cross-file security review...")
        if not await _run_pass(state, progress, 4, "holistic", run_holistic):
            return await _merge_and_finish(state, progress, total_passes, start)
        h_count = len(state.holistic_result.findings) if state.holistic_result else 0
        progress(4, "holistic", "done", f"{h_count} new findings")

        # Pass 5: Config review
        progress(5, "config_review", "running", "LLM reviewing config files...")
        if not await _run_pass(state, progress, 5, "config_review", run_config_review):
            return await _merge_and_finish(state, progress, total_passes, start)
        c_count = len(state.config_review_result.findings) if state.config_review_result else 0
        progress(5, "config_review", "done", f"{c_count} config findings")

    elif mode == "sast-triage":
        # Pass 3: Triage
        progress(3, "triage", "running", "LLM triaging SAST findings...")
        if not await _run_pass(state, progress, 3, "triage", run_triage):
            return await _merge_and_finish(state, progress, total_passes, start)
        if state.triage_result:
            t = state.triage_result
            progress(3, "triage", "done",
                     f"{t.total_confirmed} confirmed, {t.total_false_positive} FP")
        elif any(d.pass_name == "triage" for d in state.degradations):
            progress(3, "triage", "done", "0 triaged — see coverage gaps")
        else:
            progress(3, "triage", "done", "skipped")

    return await _merge_and_finish(state, progress, total_passes, start)


async def _merge_and_finish(
    state: PipelineState,
    progress: ProgressCallback,
    total_passes: int,
    start: float,
) -> "Path":
    """Run the merge pass and report final totals. Always called, even on partial failure."""
    from security_review.passes.merge import run_merge

    merge_pass = total_passes
    progress(merge_pass, "merge", "running", "Generating SARIF report...")
    sarif_path = await run_merge(state)

    duration_ms = int((time.monotonic() - start) * 1000)
    duration_s = duration_ms / 1000
    cost = state.cost_tracker.total_spent

    all_results = []
    for run in (state.sast_sarif or {}).get("runs", []):
        all_results.extend(run.get("results", []))
    total_findings = len(all_results)
    if state.holistic_result:
        total_findings += len(state.holistic_result.findings)
    if state.config_review_result:
        total_findings += len(state.config_review_result.findings)

    detail = f"{total_findings} total findings, ${cost:.2f} LLM cost, {duration_s:.1f}s"
    if state.errors:
        detail += f" -- {len(state.errors)} pass(es) failed, partial results"
    progress(merge_pass, "merge", "done", detail)

    logger.info(
        "pipeline.completed",
        duration_ms=duration_ms,
        total_cost_usd=cost,
        pass_failures=len(state.errors),
    )

    return sarif_path
