"""Pipeline orchestrator: run_pipeline().

The pipeline is linear — no pass runs concurrently with another.
Within a pass, tools/batches may run concurrently.
"""
from __future__ import annotations

import time

import structlog

from security_review.passes.state import PipelineState, ProgressCallback

logger = structlog.get_logger()


def _safe_progress(callback: ProgressCallback, pass_number: int, pass_name: str, status: str, detail: str) -> None:
    """Call progress callback, swallowing any exceptions."""
    try:
        callback(pass_number, pass_name, status, detail)
    except Exception as e:
        logger.debug("progress.callback_failed", error=str(e))


# Re-export so existing imports from pipeline still work
__all__ = ["PipelineState", "ProgressCallback", "run_pipeline"]


async def run_pipeline(state: PipelineState) -> "Path":
    """Execute the 5-pass pipeline. Returns path to final SARIF."""
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
    await run_inventory(state)
    file_count = state.manifest.total_files if state.manifest else 0
    langs = state.manifest.languages if state.manifest else {}
    lang_str = ", ".join(f"{v} {k}" for k, v in sorted(langs.items(), key=lambda x: -x[1]) if v > 0)
    progress(1, "inventory", "done", f"{file_count} files ({lang_str})")

    # Pass 2: SAST
    progress(2, "sast", "running", "Running SAST tools...")
    await run_sast(state)
    sast_count = sum(
        len(run.get("results", []))
        for run in (state.sast_sarif or {}).get("runs", [])
    )
    progress(2, "sast", "done", f"{sast_count} findings")

    if mode == "full":
        # Pass 3: Triage
        progress(3, "triage", "running", "LLM triaging SAST findings...")
        await run_triage(state)
        if state.triage_result:
            t = state.triage_result
            progress(3, "triage", "done",
                     f"{t.total_confirmed} confirmed, {t.total_false_positive} FP, "
                     f"{t.total_needs_context} needs context")
        else:
            progress(3, "triage", "done", "skipped (no findings to triage)")

        # Pass 4: Holistic
        progress(4, "holistic", "running", "LLM cross-file security review...")
        await run_holistic(state)
        h_count = len(state.holistic_result.findings) if state.holistic_result else 0
        progress(4, "holistic", "done", f"{h_count} new findings")

        # Pass 5: Config review
        progress(5, "config_review", "running", "LLM reviewing config files...")
        await run_config_review(state)
        c_count = len(state.config_review_result.findings) if state.config_review_result else 0
        progress(5, "config_review", "done", f"{c_count} config findings")

    elif mode == "sast-triage":
        # Pass 3: Triage
        progress(3, "triage", "running", "LLM triaging SAST findings...")
        await run_triage(state)
        if state.triage_result:
            t = state.triage_result
            progress(3, "triage", "done",
                     f"{t.total_confirmed} confirmed, {t.total_false_positive} FP")
        else:
            progress(3, "triage", "done", "skipped")

    # Merge
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

    progress(merge_pass, "merge", "done",
             f"{total_findings} total findings, ${cost:.2f} LLM cost, {duration_s:.1f}s")

    logger.info(
        "pipeline.completed",
        duration_ms=duration_ms,
        total_cost_usd=cost,
    )

    return sarif_path
