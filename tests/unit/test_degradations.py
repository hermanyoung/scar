"""Tests for the degradation ledger (Plan 018 WP1)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from rich.console import Console

from security_review import __version__
from security_review.config import load_config
from security_review.models.degradation import Degradation
from security_review.passes.merge import run_merge
from security_review.passes.state import PipelineState
from security_review.reporting.common import ReportData, render_degradations_md
from security_review.reporting.full import render_full
from security_review.reporting.summary import render_summary
from security_review.reporting.terminal import render_terminal
from security_review.run_ledger import RunLedger


def _build_state(tmp_path: Path) -> PipelineState:
    cfg = load_config(None)
    review = cfg.review.model_dump()
    review.update({
        "output_sarif": str(tmp_path / "security-report.sarif"),
        "output_summary": str(tmp_path / "security-report.md"),
        "output_triage": str(tmp_path / "triage.json"),
        "mode": "sast",
    })
    cfg = cfg.model_copy(update={"review": cfg.review.__class__.model_validate(review)})
    return PipelineState(config=cfg, target_path=tmp_path, work_dir=tmp_path)


# -- Degradation model --------------------------------------------------------


def test_degradation_valid_construction():
    d = Degradation(
        pass_name="sast", kind="tool_missing", subject="bandit",
        detail="binary 'bandit' not found on PATH — bandit did not run",
    )
    assert d.count == 0
    assert d.subject == "bandit"


def test_degradation_rejects_unknown_field():
    with pytest.raises(ValidationError):
        Degradation(
            pass_name="sast", kind="tool_missing", subject="bandit",
            detail="x", bogus="not allowed",
        )


def test_degradation_rejects_invalid_kind():
    with pytest.raises(ValidationError):
        Degradation(pass_name="sast", kind="not_a_real_kind", subject="bandit", detail="x")


# -- PipelineState.degrade ----------------------------------------------------


def test_pipeline_state_degrade_appends(tmp_path: Path):
    state = _build_state(tmp_path)
    assert state.degradations == []
    d = Degradation(pass_name="sast", kind="tool_missing", subject="bandit", detail="x")
    state.degrade(d)
    assert state.degradations == [d]


# -- render_degradations_md ---------------------------------------------------


def test_render_degradations_md_empty():
    assert render_degradations_md([]) == []


def test_render_degradations_md_non_empty():
    d = Degradation(pass_name="sast", kind="tool_missing", subject="bandit", detail="binary missing")
    lines = render_degradations_md([d])
    assert any("Coverage Gaps & Failures" in line for line in lines)
    assert any("[sast] tool_missing" in line and "bandit" in line for line in lines)


# -- Markdown renderers --------------------------------------------------------


def test_render_summary_coverage_gaps_zero_when_clean():
    data = ReportData()
    assert "**Coverage Gaps:** 0" in render_summary(data)
    assert "Coverage Gaps & Failures" not in render_summary(data)


def test_render_summary_coverage_gaps_section_when_degraded():
    d = Degradation(pass_name="sast", kind="tool_missing", subject="bandit", detail="binary missing")
    data = ReportData(degradations=[d])
    out = render_summary(data)
    assert "**Coverage Gaps:** 1" in out
    assert "Coverage Gaps & Failures" in out


def test_render_full_coverage_gaps_zero_when_clean():
    data = ReportData()
    assert "**Coverage Gaps:** 0" in render_full(data)


def test_render_full_coverage_gaps_section_when_degraded():
    d = Degradation(pass_name="holistic", kind="check_failed", subject="CWE-863", detail="failed after retry")
    data = ReportData(degradations=[d])
    out = render_full(data)
    assert "**Coverage Gaps:** 1" in out
    assert "Coverage Gaps & Failures" in out


# -- Terminal renderer ---------------------------------------------------------


def test_render_terminal_prints_panel_with_zero_findings():
    d = Degradation(pass_name="sast", kind="tool_missing", subject="bandit", detail="binary missing")
    data = ReportData(total=0, degradations=[d])
    console = Console(record=True, width=120)
    render_terminal(data, console=console)
    out = console.export_text()
    assert "Coverage Gaps & Failures" in out
    assert "No findings." in out


# -- Merge invocation ----------------------------------------------------------


async def test_merge_invocation_marks_execution_unsuccessful(tmp_path: Path):
    state = _build_state(tmp_path)
    state.degrade(Degradation(
        pass_name="sast", kind="tool_missing", subject="bandit", detail="binary missing",
    ))

    sarif_path = await run_merge(state)

    with open(sarif_path, encoding="utf-8") as f:
        sarif = json.load(f)
    invocation = sarif["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert len(invocation["properties"]["degradations"]) == 1
    assert invocation["properties"]["scar_version"] == __version__

    triage_path = tmp_path / "triage.json"
    with open(triage_path, encoding="utf-8") as f:
        triage_data = json.load(f)
    assert triage_data["scar_version"] == __version__
    assert len(triage_data["degradations"]) == 1


async def test_merge_mirrors_degradation_to_ledger(tmp_path: Path):
    state = _build_state(tmp_path)
    state.ledger = RunLedger(tmp_path / "events.jsonl")
    state.degrade(Degradation(
        pass_name="sast", kind="tool_missing", subject="bandit", detail="binary missing",
    ))

    await run_merge(state)

    lines = (tmp_path / "events.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["kind"] == "degradation"
    assert event["degradation_kind"] == "tool_missing"
    assert event["subject"] == "bandit"
