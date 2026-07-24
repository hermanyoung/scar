"""Tests for holistic empty-response integrity (Plan 021 WP-A).

An empty/whitespace LLM response must never be recorded as a clean,
covered check — it means the model never answered. This is a false-clean
integrity bug: without this fix, an empty response is indistinguishable
from a verified-clean check (see plan 021 §2).
"""
from __future__ import annotations

from pathlib import Path

from pydantic_ai.messages import ModelResponse, TextPart
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.profiles import ModelProfile

from security_review.checks import CWECheck
from security_review.config import load_config
from security_review.models.inventory import FileEntry, FileManifest
from security_review.passes.holistic import run_holistic
from security_review.passes.state import PipelineState


def _make_check(cwe_id: str = "999") -> CWECheck:
    return CWECheck(
        cwe_id=cwe_id, name="Test Check", detection="llm",
        file_types=[], check_prompt="Check for the test vulnerability.",
    )


def _make_state(tmp_path: Path) -> PipelineState:
    """Build a PipelineState with one source file, ready for run_holistic()."""
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    state = PipelineState(config=load_config(None), target_path=tmp_path, work_dir=tmp_path)
    state.manifest = FileManifest(
        files=[FileEntry(path="app.py", language="python", size_bytes=6,
                         security_weight=1, estimated_tokens=5)],
        total_files=1, total_tokens=5, languages={"python": 1},
    )
    state.sast_sarif = {"runs": []}
    return state


async def _run_with_response(monkeypatch, state: PipelineState, respond, *, cwe_id: str = "999") -> None:
    """Wire run_holistic() to a single CWE check served by `respond` (prompted-mode profile).

    Mirrors the FunctionModel/monkeypatch pattern of test_overflow.py.
    """
    prompted_model = FunctionModel(respond, profile=ModelProfile(
        supports_json_schema_output=False,
        default_structured_output_mode="prompted",
    ))
    monkeypatch.setattr(
        "security_review.passes.holistic.load_cwe_checks", lambda: [_make_check(cwe_id)],
    )
    monkeypatch.setattr(
        "security_review.passes.holistic.build_model",
        lambda model_string, llm_config: prompted_model,
    )
    monkeypatch.setattr(
        "security_review.passes.holistic.build_model_settings",
        lambda model_string, llm_config: None,
    )
    await run_holistic(state)


async def test_empty_response_is_parse_failure(tmp_path: Path, monkeypatch):
    """An always-empty response must degrade as check_failed, never complete clean."""
    def _respond(messages, info):
        return ModelResponse(parts=[TextPart(content="")])

    state = _make_state(tmp_path)
    await _run_with_response(monkeypatch, state, _respond)

    check_failed = [d for d in state.degradations if d.kind == "check_failed"]
    assert len(check_failed) == 1
    assert check_failed[0].subject == "CWE-999"

    # No check contributed to a clean result — either no holistic_result at
    # all, or one with zero findings and zero files_reviewed.
    assert state.holistic_result is None or (
        state.holistic_result.findings == [] and state.holistic_result.files_reviewed == []
    )


async def test_no_findings_answer_still_completes_clean(tmp_path: Path, monkeypatch):
    """The legitimate clean path (explicit 'No findings.') must not regress."""
    def _respond(messages, info):
        return ModelResponse(parts=[TextPart(content="No findings.")])

    state = _make_state(tmp_path)
    await _run_with_response(monkeypatch, state, _respond)

    assert [d for d in state.degradations if d.kind in ("check_failed", "parse_failed")] == []
    assert state.holistic_result is not None
    assert state.holistic_result.findings == []
    assert state.holistic_result.files_reviewed == ["app.py"]


async def test_unparseable_nonempty_still_retries(tmp_path: Path, monkeypatch):
    """Non-empty, unparseable text is a pre-existing parse failure, unchanged by this fix."""
    def _respond(messages, info):
        return ModelResponse(parts=[TextPart(content="I looked at the code, seems fine I guess")])

    state = _make_state(tmp_path)
    await _run_with_response(monkeypatch, state, _respond)

    check_failed = [d for d in state.degradations if d.kind == "check_failed"]
    assert len(check_failed) == 1
    assert check_failed[0].subject == "CWE-999"
    assert state.holistic_result is None or state.holistic_result.findings == []
