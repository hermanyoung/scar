"""Shared concurrent-batch driver for the LLM passes (Pass 3/4/6).

Extracted from triage.py / holistic.py so the verify pass (plan 020) does
not add a third hand-rolled copy of the same loop. The driver owns the
mechanics that were identical in both passes:

  - iterate items in ``llm.concurrency``-sized batches
  - budget-gate each batch via ``cost_tracker.would_exceed_budget``
  - ``asyncio.gather(return_exceptions=True)`` within a batch
  - re-raise fatal errors (``is_fatal_error``) after the caller has had a
    chance to record them via ``on_result``
  - emit the standard pre/post-batch ``counter`` progress lines with
    elapsed / ETA / cumulative cost

Everything pass-specific (what a result means, budget-exhaustion
degradations, the counter summary text) stays in the calling pass via
callables — the 018/019 behaviours woven into those loops (degradations,
ledger appends, holistic OVERFLOW handling) are preserved verbatim.
"""
from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Sequence
from typing import Any

import structlog

from security_review.errors import is_fatal_error
from security_review.passes.state import PipelineState

logger = structlog.get_logger()


async def run_in_batches(
    items: Sequence[Any],
    *,
    state: PipelineState,
    pass_number: int,
    pass_name: str,
    make_coro: Callable[[Any, int], Awaitable[Any]],
    on_result: Callable[[Any, int, Any], None],
    describe: Callable[[Sequence[Any], int], str],
    summarize: Callable[[], str],
    on_budget_exhausted: Callable[[int, int], None],
) -> None:
    """Drive ``items`` through concurrent batches with budget gating.

    Args:
        items: Work items, processed in order in batches of
            ``state.config.llm.concurrency``.
        state: Pipeline state (config, cost tracker, progress callback).
        pass_number/pass_name: Used for the progress counter lines.
        make_coro: ``(item, index) -> coroutine`` building the per-item call.
        on_result: ``(item, index, result_or_exception) -> None`` records each
            outcome (write-back / collect / mutate). Called for exceptions
            too; fatal exceptions are re-raised by the driver *after*
            ``on_result`` returns, so the pass can log/count first.
        describe: ``(batch, start_index) -> str`` pre-batch counter detail.
        summarize: ``() -> str`` post-batch counter detail (running totals).
        on_budget_exhausted: ``(start_index, remaining) -> None`` called once
            when the cumulative budget is reached; the driver then stops
            dispatching (the pass records its own degradation/progress).
    """
    concurrency = state.config.llm.concurrency
    total = len(items)
    processed = 0
    t_start = time.monotonic()

    for batch_start in range(0, total, concurrency):
        if state.cost_tracker.would_exceed_budget(state.config.llm.max_budget_usd):
            on_budget_exhausted(batch_start, total - batch_start)
            break

        batch = items[batch_start:batch_start + concurrency]

        # Pre-batch progress with timing/ETA
        elapsed = time.monotonic() - t_start
        if processed > 0:
            avg = elapsed / processed
            eta = f"~{int((total - processed) * avg)}s left"
        else:
            eta = "estimating..."
        state.on_progress(
            pass_number, pass_name, "counter",
            f"[{processed}/{total}] {describe(batch, batch_start)} "
            f"({int(elapsed)}s elapsed, {eta}, ${state.cost_tracker.total_spent:.2f})",
        )

        tasks = [make_coro(item, batch_start + j) for j, item in enumerate(batch)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for j, result in enumerate(results):
            on_result(batch[j], batch_start + j, result)
            processed += 1
            if isinstance(result, Exception) and is_fatal_error(result):
                raise result

        # Post-batch progress with running totals and timing/ETA
        elapsed = time.monotonic() - t_start
        if 0 < processed < total:
            avg = elapsed / processed
            eta = f" ~{int((total - processed) * avg)}s left"
        else:
            eta = ""
        state.on_progress(
            pass_number, pass_name, "counter",
            f"[{processed}/{total}] {summarize()} "
            f"({int(elapsed)}s{eta}, ${state.cost_tracker.total_spent:.2f})",
        )
