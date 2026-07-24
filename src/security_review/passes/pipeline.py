"""Pipeline orchestrator: run_pipeline().

The pipeline is linear — no pass runs concurrently with another.
Within a pass, tools/batches may run concurrently.
"""
from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from enum import Enum, auto
from pathlib import Path

import structlog

from code_analysis.models import CallGraph
from security_review.errors import is_fatal_error
from security_review.models.degradation import Degradation
from security_review.passes.checkpoint import completed_passes, init_run, save_pass
from security_review.passes.state import PassError, PipelineState, ProgressCallback

logger = structlog.get_logger()


def _safe_progress(callback: ProgressCallback, pass_number: int, pass_name: str, status: str, detail: str) -> None:
    """Call progress callback, swallowing any exceptions."""
    try:
        callback(pass_number, pass_name, status, detail)
    except Exception as e:
        logger.debug("progress.callback_failed", error=str(e))


def find_csharp_project(target_path: Path) -> Path | None:
    """Find a .sln (preferred) or .csproj under target_path for the Roslyn tool."""
    solutions = sorted(target_path.rglob("*.sln"))
    if solutions:
        return solutions[0]
    projects = sorted(target_path.rglob("*.csproj"))
    return projects[0] if projects else None


def _build_call_graph_if_available(state: PipelineState) -> tuple["CallGraph | None", "dict[str, float] | None"]:
    """Build the call graph from Pass 1's manifest. Returns (None, None) if unavailable.

    Persists to SCAR's own var/cache/graphs/<target-key>/graph.db so unchanged
    files are not re-parsed on the next run against the same target (Phase 2
    incrementalism); never writes into the target repo (plan 021 WP-D).
    Optional and best-effort -- run_holistic() degrades to keyword-only file
    selection when this returns (None, None), so a failure here never halts
    the pipeline (P6: fail loud for fatal errors, but this isn't one).
    """
    if state.manifest is None:
        return None, None
    try:
        from code_analysis import analyze, compute_call_graph_pagerank
        from code_analysis.call_graph import build_call_graph_incremental
        from code_analysis.store import GraphStore, target_cache_dir

        metrics = analyze(state.target_path, include_graph=True)
        if not metrics.modules:
            return None, None

        python_files = [
            state.target_path / f.path
            for f in state.manifest.files
            if f.language == "python"
        ]
        csharp_solution = find_csharp_project(state.target_path)

        with GraphStore(target_cache_dir(state.target_path) / "graph.db") as store:
            graph = build_call_graph_incremental(
                state.target_path, metrics.modules, store,
                python_files=python_files or None,
                csharp_solution=csharp_solution,
            )
        pagerank = compute_call_graph_pagerank(graph)
        logger.info(
            "pipeline.call_graph_built",
            nodes=len(graph.nodes),
            call_edges=len(graph.call_edges),
            entry_points=len(graph.entry_points),
            sinks=sum(len(v) for v in graph.sinks.values()),
        )
        return graph, pagerank
    except Exception as e:
        logger.warning(
            "pipeline.call_graph_failed",
            error=str(e),
            error_type=type(e).__name__,
        )
        state.degrade(Degradation(
            pass_name="pipeline", kind="call_graph_failed", subject="call_graph",
            detail=f"call graph unavailable ({type(e).__name__}: {str(e)[:120]}) — "
                   f"holistic file selection degraded to keyword-only",
            count=0,
        ))
        return None, None


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


class _PassOutcome(Enum):
    """How a pass concluded within run_pipeline."""
    RAN = auto()        # executed and completed — checkpoint saved
    RESTORED = auto()   # skipped: checkpoint rehydrated by --resume
    FAILED = auto()     # failed outright — proceed straight to merge


async def _run_or_restore(
    state: PipelineState,
    progress: ProgressCallback,
    completed: set[str],
    pass_number: int,
    pass_name: str,
    run_fn: Callable[[PipelineState], Awaitable[None]],
    running_detail: str,
) -> _PassOutcome:
    """Run one pass, or skip it when its checkpoint was restored (--resume).

    A successfully-run pass is checkpointed immediately so a later crash
    keeps its work (plan 020 Phase 2).
    """
    progress(pass_number, pass_name, "running", running_detail)
    if pass_name in completed:
        progress(pass_number, pass_name, "done", "restored from checkpoint")
        return _PassOutcome.RESTORED
    if not await _run_pass(state, progress, pass_number, pass_name, run_fn):
        return _PassOutcome.FAILED
    save_pass(state, pass_name)
    return _PassOutcome.RAN


def _stream_partial(state: PipelineState) -> None:
    """Write the partial SARIF after an LLM pass when --stream is on."""
    if not state.stream_enabled:
        return
    from security_review.passes.merge import write_partial_sarif
    try:
        write_partial_sarif(state)
    except Exception as e:
        # Streaming is best-effort observability — never kill the run for it.
        logger.warning("stream.partial_failed", error=str(e), error_type=type(e).__name__)


async def run_pipeline(state: PipelineState) -> "Path":
    """Execute the pipeline (7 passes in full mode). Returns path to final SARIF.

    If a pass fails outright, remaining passes are skipped (they generally
    depend on earlier state) but the pipeline still proceeds to merge, so
    whatever completed before the failure is written to a report instead of
    being silently discarded. Failures are recorded on state.errors and
    surfaced in the report (Principle P6 — partial failures must be visible).

    Each completed pass is checkpointed to {run_dir}/state/ so a killed run
    can be continued with --resume (state.resume skips restored passes).
    """
    from security_review.passes.config_review import run_config_review
    from security_review.passes.holistic import run_holistic
    from security_review.passes.inventory import run_inventory
    from security_review.passes.merge import run_merge
    from security_review.passes.sast import run_sast
    from security_review.passes.triage import run_triage
    from security_review.passes.verify import run_verification

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
        total_passes = 7
    elif mode == "sast-triage":
        total_passes = 4
    else:
        total_passes = 3

    # Checkpointing (plan 020 Phase 2): snapshot config + output paths, and
    # on --resume, skip passes whose checkpoints were rehydrated by the CLI.
    init_run(state)
    completed = completed_passes(state.output_dir) if state.resume else set()
    if completed:
        logger.info("pipeline.resuming", restored_passes=sorted(completed))

    # Pass 1: Inventory
    outcome = await _run_or_restore(state, progress, completed, 1, "inventory",
                                    run_inventory, "Discovering files...")
    if outcome is _PassOutcome.FAILED:
        return await _merge_and_finish(state, progress, total_passes, start)
    if outcome is _PassOutcome.RAN:
        file_count = state.manifest.total_files if state.manifest else 0
        langs = state.manifest.languages if state.manifest else {}
        lang_str = ", ".join(f"{v} {k}" for k, v in sorted(langs.items(), key=lambda x: -x[1]) if v > 0)
        progress(1, "inventory", "done", f"{file_count} files ({lang_str})")

    # Pass 2: SAST
    outcome = await _run_or_restore(state, progress, completed, 2, "sast",
                                    run_sast, "Running SAST tools...")
    if outcome is _PassOutcome.FAILED:
        return await _merge_and_finish(state, progress, total_passes, start)
    if outcome is _PassOutcome.RAN:
        sast_count = sum(
            len(run.get("results", []))
            for run in (state.sast_sarif or {}).get("runs", [])
        )
        progress(2, "sast", "done", f"{sast_count} findings")

    if mode == "full":
        # Pass 3: Triage
        outcome = await _run_or_restore(state, progress, completed, 3, "triage",
                                        run_triage, "LLM triaging SAST findings...")
        if outcome is _PassOutcome.FAILED:
            return await _merge_and_finish(state, progress, total_passes, start)
        if outcome is _PassOutcome.RAN:
            if state.triage_result:
                t = state.triage_result
                progress(3, "triage", "done",
                         f"{t.total_confirmed} confirmed, {t.total_false_positive} FP, "
                         f"{t.total_needs_context} needs context")
            elif any(d.pass_name == "triage" for d in state.degradations):
                progress(3, "triage", "done", "0 triaged — see coverage gaps")
            else:
                progress(3, "triage", "done", "skipped (no findings to triage)")
            _stream_partial(state)

        # Build the call graph (optional, best-effort) so Pass 4's file
        # selection can walk from sinks/entry-points instead of keywords alone.
        state.call_graph, state.pagerank = _build_call_graph_if_available(state)

        # Pass 4: Holistic
        outcome = await _run_or_restore(state, progress, completed, 4, "holistic",
                                        run_holistic, "LLM cross-file security review...")
        if outcome is _PassOutcome.FAILED:
            return await _merge_and_finish(state, progress, total_passes, start)
        if outcome is _PassOutcome.RAN:
            h_count = len(state.holistic_result.findings) if state.holistic_result else 0
            progress(4, "holistic", "done", f"{h_count} new findings")
            _stream_partial(state)

        # Pass 5: Config review
        outcome = await _run_or_restore(state, progress, completed, 5, "config_review",
                                        run_config_review, "LLM reviewing config files...")
        if outcome is _PassOutcome.FAILED:
            return await _merge_and_finish(state, progress, total_passes, start)
        if outcome is _PassOutcome.RAN:
            c_count = len(state.config_review_result.findings) if state.config_review_result else 0
            progress(5, "config_review", "done", f"{c_count} config findings")

        # Pass 6: Verify — independent adversarial verdicts on LLM findings
        outcome = await _run_or_restore(state, progress, completed, 6, "verify",
                                        run_verification, "LLM verifying discovered findings...")
        if outcome is _PassOutcome.FAILED:
            return await _merge_and_finish(state, progress, total_passes, start)
        if outcome is _PassOutcome.RAN:
            progress(6, "verify", "done", _verify_done_detail(state))
            _stream_partial(state)

    elif mode == "sast-triage":
        # Pass 3: Triage
        outcome = await _run_or_restore(state, progress, completed, 3, "triage",
                                        run_triage, "LLM triaging SAST findings...")
        if outcome is _PassOutcome.FAILED:
            return await _merge_and_finish(state, progress, total_passes, start)
        if outcome is _PassOutcome.RAN:
            if state.triage_result:
                t = state.triage_result
                progress(3, "triage", "done",
                         f"{t.total_confirmed} confirmed, {t.total_false_positive} FP")
            elif any(d.pass_name == "triage" for d in state.degradations):
                progress(3, "triage", "done", "0 triaged — see coverage gaps")
            else:
                progress(3, "triage", "done", "skipped")
            _stream_partial(state)

    return await _merge_and_finish(state, progress, total_passes, start)


def _verify_done_detail(state: PipelineState) -> str:
    """Build the Pass 6 'done' progress detail from the verdicts set on findings."""
    if not state.config.verification.enabled:
        return "skipped (verification disabled)"
    llm_findings = []
    if state.holistic_result:
        llm_findings += state.holistic_result.findings
    if state.config_review_result:
        llm_findings += state.config_review_result.findings
    verdicts = [f.triage_verdict for f in llm_findings if f.triage_verdict]
    if not verdicts:
        return "no LLM findings to verify"
    return (
        f"{verdicts.count('CONFIRMED')} confirmed, "
        f"{verdicts.count('FALSE_POSITIVE')} FP, "
        f"{verdicts.count('NEEDS_CONTEXT')} needs context"
    )


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
