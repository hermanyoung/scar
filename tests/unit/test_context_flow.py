"""Tests for truthful LLM coverage — files_reviewed matches what actually
fit in the prompt, and coverage claims match the pipeline mode (Plan 018 WP2).
"""
from __future__ import annotations

from pathlib import Path

from pydantic_ai.messages import ModelResponse, TextPart
from pydantic_ai.models.function import FunctionModel

from security_review.budget import CostTracker, ModelPricing
from security_review.checks import CWECheck
from security_review.config import load_config
from security_review.models.inventory import FileEntry, FileManifest
from security_review.passes.holistic import _build_inline_prompt, run_single_check
from security_review.passes.inventory import _build_coverage_report
from security_review.passes.state import PipelineState


def _make_check() -> CWECheck:
    return CWECheck(
        cwe_id="999", name="Test Check", detection="llm",
        file_types=[], check_prompt="Check for the test vulnerability.",
    )


def test_build_inline_prompt_omits_files_over_budget(tmp_path: Path):
    (tmp_path / "first.py").write_text("x" * 400_000, encoding="utf-8")
    (tmp_path / "second.py").write_text("y" * 40, encoding="utf-8")
    (tmp_path / "third.py").write_text("z" * 40, encoding="utf-8")

    prompt, included, omitted = _build_inline_prompt(
        check=_make_check(),
        file_paths=["first.py", "second.py", "third.py"],
        target_path=tmp_path,
        sast_sarif={},
        max_input_tokens=5000,
    )

    assert included == ["first.py"]
    assert omitted == ["second.py", "third.py"]
    assert "**Note:** 2 file(s) omitted" in prompt


async def test_run_single_check_files_reviewed_matches_included_not_selection(tmp_path: Path):
    (tmp_path / "first.py").write_text("x" * 400_000, encoding="utf-8")
    (tmp_path / "second.py").write_text("y" * 40, encoding="utf-8")

    def _respond(messages, info):
        return ModelResponse(parts=[TextPart(content="No findings.")])

    cfg = load_config(None)
    cfg = cfg.model_copy(update={"llm": cfg.llm.model_copy(update={"max_tokens_per_batch": 5000})})
    state = PipelineState(config=cfg, target_path=tmp_path, work_dir=tmp_path)
    state.manifest = FileManifest(files=[], total_files=0, total_tokens=0, languages={})
    state.sast_sarif = {"runs": []}
    state.cost_tracker = CostTracker(
        pricing={"test:model": ModelPricing(input_per_token=0.0, output_per_token=0.0)},
    )

    result = await run_single_check(
        check=_make_check(),
        file_paths=["first.py", "second.py"],
        state=state,
        model=FunctionModel(_respond),
        model_string="test:model",
    )

    assert result is not None
    findings, files_reviewed, parse_failed = result
    assert files_reviewed == ["first.py"]
    assert files_reviewed != ["first.py", "second.py"]

    omitted_degradations = [d for d in state.degradations if d.kind == "files_omitted"]
    assert len(omitted_degradations) == 1
    assert omitted_degradations[0].subject == "CWE-999"
    assert omitted_degradations[0].count == 1


def test_build_coverage_report_gates_semantic_passes_by_mode():
    entries = [FileEntry(path="app.py", language="python", size_bytes=10,
                          security_weight=1, estimated_tokens=5)]
    languages = {"python": 1}

    sast_report = _build_coverage_report(entries, languages, "sast")
    assert sast_report.by_type["python"].semantic_passes == []

    full_report = _build_coverage_report(entries, languages, "full")
    assert full_report.by_type["python"].semantic_passes == ["Holistic"]
