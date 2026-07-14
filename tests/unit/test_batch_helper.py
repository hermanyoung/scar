"""Tests for the shared concurrent-batch driver (Plan 020 §1.5.1)."""
from __future__ import annotations

from pathlib import Path

import pytest

from security_review.config import load_config
from security_review.errors import ConfigurationError
from security_review.passes._batch import run_in_batches
from security_review.passes.state import PipelineState


class _FakeTracker:
    """Cost-tracker stand-in with a scriptable budget gate."""

    def __init__(self, exceed_after_batches: int | None = None):
        self._exceed_after = exceed_after_batches
        self.gate_checks = 0

    def would_exceed_budget(self, max_budget_usd: float) -> bool:
        self.gate_checks += 1
        if self._exceed_after is None:
            return False
        return self.gate_checks > self._exceed_after

    @property
    def total_spent(self) -> float:
        return 0.0


def _make_state(tmp_path: Path, *, concurrency: int = 2) -> PipelineState:
    cfg = load_config(None)
    cfg = cfg.model_copy(update={
        "llm": cfg.llm.model_copy(update={"concurrency": concurrency}),
    })
    return PipelineState(config=cfg, target_path=tmp_path, work_dir=tmp_path)


async def test_run_in_batches_processes_all_items_in_order(tmp_path: Path):
    state = _make_state(tmp_path, concurrency=2)
    state.cost_tracker = _FakeTracker()

    seen: list[tuple[int, str]] = []

    async def _work(item, index):
        return item.upper()

    def _on_result(item, index, result):
        seen.append((index, result))

    await run_in_batches(
        ["a", "b", "c", "d", "e"],
        state=state, pass_number=3, pass_name="triage",
        make_coro=_work, on_result=_on_result,
        describe=lambda batch, start: f"batch at {start}",
        summarize=lambda: "summary",
        on_budget_exhausted=lambda start, remaining: pytest.fail("budget gate must not fire"),
    )

    assert seen == [(0, "A"), (1, "B"), (2, "C"), (3, "D"), (4, "E")]


async def test_run_in_batches_emits_counter_lines_per_batch(tmp_path: Path):
    state = _make_state(tmp_path, concurrency=2)
    state.cost_tracker = _FakeTracker()

    counters: list[str] = []

    def _progress(pass_number, pass_name, status, detail):
        if status == "counter":
            counters.append(detail)

    state.on_progress = _progress

    async def _work(item, index):
        return item

    await run_in_batches(
        [1, 2, 3],
        state=state, pass_number=4, pass_name="holistic",
        make_coro=_work, on_result=lambda item, index, result: None,
        describe=lambda batch, start: f"items {start}",
        summarize=lambda: "running totals",
        on_budget_exhausted=lambda start, remaining: None,
    )

    # 2 batches (2 + 1) -> one pre-batch and one post-batch line each.
    assert len(counters) == 4
    assert counters[0].startswith("[0/3] items 0")
    assert "running totals" in counters[1]
    assert counters[2].startswith("[2/3] items 2")
    assert counters[3].startswith("[3/3] running totals")


async def test_run_in_batches_budget_gate_stops_dispatch(tmp_path: Path):
    state = _make_state(tmp_path, concurrency=2)
    state.cost_tracker = _FakeTracker(exceed_after_batches=1)

    processed: list[int] = []
    exhausted: list[tuple[int, int]] = []

    async def _work(item, index):
        return item

    await run_in_batches(
        [1, 2, 3, 4, 5, 6],
        state=state, pass_number=3, pass_name="triage",
        make_coro=_work,
        on_result=lambda item, index, result: processed.append(index),
        describe=lambda batch, start: "x",
        summarize=lambda: "y",
        on_budget_exhausted=lambda start, remaining: exhausted.append((start, remaining)),
    )

    # First batch (2 items) ran; the gate fired before the second batch.
    assert processed == [0, 1]
    assert exhausted == [(2, 4)]


async def test_run_in_batches_reraises_fatal_error_after_on_result(tmp_path: Path):
    state = _make_state(tmp_path, concurrency=2)
    state.cost_tracker = _FakeTracker()

    recorded: list[type] = []

    async def _work(item, index):
        if item == "fatal":
            raise ConfigurationError("bad config", code="SYS_CONFIG_INVALID")
        return item

    def _on_result(item, index, result):
        recorded.append(type(result))

    with pytest.raises(ConfigurationError):
        await run_in_batches(
            ["ok", "fatal", "never-dispatched"],
            state=state, pass_number=3, pass_name="triage",
            make_coro=_work, on_result=_on_result,
            describe=lambda batch, start: "x",
            summarize=lambda: "y",
            on_budget_exhausted=lambda start, remaining: None,
        )

    # on_result saw both the success and the fatal exception before the raise.
    assert recorded == [str, ConfigurationError]


async def test_run_in_batches_nonfatal_error_passed_to_on_result_and_continues(tmp_path: Path):
    state = _make_state(tmp_path, concurrency=2)
    state.cost_tracker = _FakeTracker()

    outcomes: list[object] = []

    async def _work(item, index):
        if item == "boom":
            raise RuntimeError("transient")
        return item

    await run_in_batches(
        ["a", "boom", "c"],
        state=state, pass_number=3, pass_name="triage",
        make_coro=_work,
        on_result=lambda item, index, result: outcomes.append(result),
        describe=lambda batch, start: "x",
        summarize=lambda: "y",
        on_budget_exhausted=lambda start, remaining: None,
    )

    assert outcomes[0] == "a"
    assert isinstance(outcomes[1], RuntimeError)
    assert outcomes[2] == "c"
